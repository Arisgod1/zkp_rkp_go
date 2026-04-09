package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/Arisgod1/zkp_rkp_go/internal/audit"
	"github.com/Arisgod1/zkp_rkp_go/internal/auth"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/Arisgod1/zkp_rkp_go/internal/model"
	"github.com/Arisgod1/zkp_rkp_go/internal/repository"
)

type AuthService struct {
	repo           *repository.UserRepository
	rdb            *redis.Client
	jwtManager     *auth.JWTManager
	p              *big.Int
	q              *big.Int
	g              *big.Int
	challengeTTL   time.Duration
	auditPublisher audit.Publisher
}

var getAndDeleteChallengeScript = redis.NewScript(`
local val = redis.call('GET', KEYS[1])
if val then
  redis.call('DEL', KEYS[1])
end
return val
`)

func NewAuthService(
	repo *repository.UserRepository,
	rdb *redis.Client,
	jwtManager *auth.JWTManager,
	p, q, g *big.Int,
	challengeTTL time.Duration,
	auditPublisher audit.Publisher,
) *AuthService {
	if auditPublisher == nil {
		auditPublisher = audit.NewNoopPublisher()
	}
	return &AuthService{
		repo:           repo,
		rdb:            rdb,
		jwtManager:     jwtManager,
		p:              p,
		q:              q,
		g:              g,
		challengeTTL:   challengeTTL,
		auditPublisher: auditPublisher,
	}
}

// ====== 工具函数 ======

func computeChallengeHex(clientRHex, publicYHex, username string) string {
	raw := clientRHex + "|" + publicYHex + "|" + username
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func mustBigFromHex(h string) (*big.Int, error) {
	n := new(big.Int)
	_, ok := n.SetString(h, 16)
	if !ok {
		return nil, errors.New("invalid hex big integer")
	}
	return n, nil
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v := ctx.Value("requestId")
	id, _ := v.(string)
	return id
}

// ====== 业务方法 ======

func (s *AuthService) Register(ctx context.Context, req model.RegisterRequest) (retErr error) {
	reason := ""
	defer func() {
		_ = s.auditPublisher.Publish(ctx, audit.Event{
			EventID:    uuid.NewString(),
			EventType:  audit.EventRegister,
			Username:   req.Username,
			Success:    retErr == nil,
			Reason:     reason,
			RequestID:  requestIDFromContext(ctx),
			OccurredAt: time.Now().UTC(),
		})
	}()

	if req.Username == "" || req.PublicKeyY == "" || req.Salt == "" {
		reason = "invalid_input"
		retErr = errors.New("username/publicKeyY/salt cannot be empty")
		return
	}

	count, err := s.repo.CountByUsername(req.Username)
	if err != nil {
		reason = "count_error"
		retErr = err
		return
	}
	if count > 0 {
		reason = "username_exists"
		retErr = errors.New("username already exists")
		return
	}

	if err := s.repo.Create(&model.UserCredentials{
		Username:   req.Username,
		PublicKeyY: req.PublicKeyY,
		Salt:       req.Salt,
	}); err != nil {
		reason = "db_error"
		retErr = err
		return
	}

	return
}

func (s *AuthService) Challenge(ctx context.Context, req model.ChallengeRequest) (retResp map[string]any, retErr error) {
	reason := ""
	challengeID := ""
	defer func() {
		_ = s.auditPublisher.Publish(ctx, audit.Event{
			EventID:     uuid.NewString(),
			EventType:   audit.EventChallenge,
			Username:    req.Username,
			Success:     retErr == nil,
			Reason:      reason,
			RequestID:   requestIDFromContext(ctx),
			ChallengeID: challengeID,
			OccurredAt:  time.Now().UTC(),
		})
	}()

	if req.Username == "" || req.ClientR == "" {
		reason = "invalid_input"
		retErr = errors.New("username/clientR cannot be empty")
		return
	}

	user, err := s.repo.FindByUsername(req.Username)
	userExists := err == nil

	challengeID = uuid.NewString()
	var challengeHex string

	if userExists {
		challengeHex = computeChallengeHex(req.ClientR, user.PublicKeyY, req.Username)
	} else {
		// 防枚举：用户不存在也返回正常结构
		fakeY := "0000000000000000000000000000000000000000000000000000000000000000"
		challengeHex = computeChallengeHex(req.ClientR, fakeY, req.Username)
	}

	cache := model.ChallengeCache{
		Username:  req.Username,
		ClientR:   req.ClientR,
		Challenge: challengeHex,
		CreatedAt: time.Now().Unix(),
	}

	raw, _ := json.Marshal(cache)
	key := "zkp:challenge:" + challengeID

	if err := s.rdb.Set(ctx, key, raw, s.challengeTTL).Err(); err != nil {
		reason = "cache_write_failed"
		retErr = errors.New("failed to cache challenge")
		return
	}

	retResp = map[string]any{
		"challengeId": challengeID,
		"c":           challengeHex,
		"p":           s.p.Text(16),
		"q":           s.q.Text(16),
		"g":           s.g.Text(16),
	}
	return
}

func (s *AuthService) Verify(ctx context.Context, req model.VerifyRequest) (retToken string, retErr error) {
	reason := ""
	defer func() {
		_ = s.auditPublisher.Publish(ctx, audit.Event{
			EventID:     uuid.NewString(),
			EventType:   audit.EventVerify,
			Username:    req.Username,
			Success:     retErr == nil,
			Reason:      reason,
			RequestID:   requestIDFromContext(ctx),
			ChallengeID: req.ChallengeID,
			OccurredAt:  time.Now().UTC(),
		})
	}()

	if req.ChallengeID == "" || req.S == "" || req.ClientR == "" || req.Username == "" {
		reason = "invalid_input"
		retErr = errors.New("challengeId/s/clientR/username cannot be empty")
		return
	}

	key := "zkp:challenge:" + req.ChallengeID
	rawResult, err := getAndDeleteChallengeScript.Run(ctx, s.rdb, []string{key}).Result()
	if err != nil {
		reason = "challenge_not_found"
		retErr = errors.New("challenge not found or expired")
		return
	}

	raw, ok := rawResult.(string)
	if !ok || raw == "" {
		reason = "challenge_not_found"
		retErr = errors.New("challenge not found or expired")
		return
	}

	var ch model.ChallengeCache
	if err := json.Unmarshal([]byte(raw), &ch); err != nil {
		reason = "challenge_parse_failed"
		retErr = errors.New("challenge parse failed")
		return
	}

	if ch.Username != req.Username || ch.ClientR != req.ClientR {
		reason = "challenge_mismatch"
		retErr = errors.New("challenge mismatch")
		return
	}

	user, err := s.repo.FindByUsername(req.Username)
	if err != nil {
		reason = "invalid_credential"
		retErr = errors.New("invalid credential")
		return
	}

	recomputed := computeChallengeHex(req.ClientR, user.PublicKeyY, req.Username)
	if recomputed != ch.Challenge {
		reason = "challenge_invalid"
		retErr = errors.New("challenge invalid")
		return
	}

	sVal, err := mustBigFromHex(req.S)
	if err != nil {
		reason = "invalid_s"
		retErr = errors.New("invalid s")
		return
	}
	rVal, err := mustBigFromHex(req.ClientR)
	if err != nil {
		reason = "invalid_clientR"
		retErr = errors.New("invalid clientR")
		return
	}
	yVal, err := mustBigFromHex(user.PublicKeyY)
	if err != nil {
		reason = "invalid_publicKeyY"
		retErr = errors.New("invalid publicKeyY")
		return
	}
	cVal, err := mustBigFromHex(ch.Challenge)
	if err != nil {
		reason = "invalid_challenge_c"
		retErr = errors.New("invalid challenge c")
		return
	}

	left := new(big.Int).Exp(s.g, sVal, s.p)
	yc := new(big.Int).Exp(yVal, cVal, s.p)
	right := new(big.Int).Mul(rVal, yc)
	right.Mod(right, s.p)

	if left.Cmp(right) != 0 {
		reason = "invalid_proof"
		retErr = errors.New("zkp verification failed")
		return
	}
	token, err := s.jwtManager.CreateToken(req.Username)
	if err != nil {
		reason = "token_issue_failed"
		retErr = errors.New("token create failed")
		return
	}

	retToken = token
	return
}
