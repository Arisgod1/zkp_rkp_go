package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/Arisgod1/zkp_rkp_go/internal/auth"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/Arisgod1/zkp_rkp_go/internal/model"
	"github.com/Arisgod1/zkp_rkp_go/internal/repository"
)

type AuthService struct {
	repo       *repository.UserRepository
	rdb        *redis.Client
	jwtManager *auth.JWTManager
	p          *big.Int
	q          *big.Int
	g          *big.Int
}

func NewAuthService(
	repo *repository.UserRepository,
	rdb *redis.Client,
	jwtManager *auth.JWTManager,
	p, q, g *big.Int,
) *AuthService {
	return &AuthService{
		repo:       repo,
		rdb:        rdb,
		jwtManager: jwtManager,
		p:          p,
		q:          q,
		g:          g,
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

// ====== 业务方法 ======

func (s *AuthService) Register(ctx context.Context, req model.RegisterRequest) error {
	_ = ctx // 目前 repo 用 gorm，后续可透传到 db.WithContext(ctx)

	if req.Username == "" || req.PublicKeyY == "" || req.Salt == "" {
		return errors.New("username/publicKeyY/salt cannot be empty")
	}

	count, err := s.repo.CountByUsername(req.Username)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("username already exists")
	}

	return s.repo.Create(&model.UserCredentials{
		Username:   req.Username,
		PublicKeyY: req.PublicKeyY,
		Salt:       req.Salt,
	})
}

func (s *AuthService) Challenge(ctx context.Context, req model.ChallengeRequest) (map[string]any, error) {
	if req.Username == "" || req.ClientR == "" {
		return nil, errors.New("username/clientR cannot be empty")
	}

	user, err := s.repo.FindByUsername(req.Username)
	userExists := err == nil

	challengeID := uuid.NewString()
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

	if err := s.rdb.Set(ctx, key, raw, 300*time.Second).Err(); err != nil {
		return nil, errors.New("failed to cache challenge")
	}

	return map[string]any{
		"challengeId": challengeID,
		"c":           challengeHex,
		"p":           s.p.Text(16),
		"q":           s.q.Text(16),
		"g":           s.g.Text(16),
	}, nil
}

func (s *AuthService) Verify(ctx context.Context, req model.VerifyRequest) (string, error) {
	if req.ChallengeID == "" || req.S == "" || req.ClientR == "" || req.Username == "" {
		return "", errors.New("challengeId/s/clientR/username cannot be empty")
	}

	key := "zkp:challenge:" + req.ChallengeID
	raw, err := s.rdb.Get(ctx, key).Result()
	if err != nil {
		return "", errors.New("challenge not found or expired")
	}
	// 验证是否成功都删除 challenge，防重放
	_ = s.rdb.Del(ctx, key).Err()

	var ch model.ChallengeCache
	if err := json.Unmarshal([]byte(raw), &ch); err != nil {
		return "", errors.New("challenge parse failed")
	}

	if ch.Username != req.Username || ch.ClientR != req.ClientR {
		return "", errors.New("challenge mismatch")
	}

	user, err := s.repo.FindByUsername(req.Username)
	if err != nil {
		return "", errors.New("invalid credential")
	}

	recomputed := computeChallengeHex(req.ClientR, user.PublicKeyY, req.Username)
	if recomputed != ch.Challenge {
		return "", errors.New("challenge invalid")
	}

	sVal, err := mustBigFromHex(req.S)
	if err != nil {
		return "", errors.New("invalid s")
	}
	rVal, err := mustBigFromHex(req.ClientR)
	if err != nil {
		return "", errors.New("invalid clientR")
	}
	yVal, err := mustBigFromHex(user.PublicKeyY)
	if err != nil {
		return "", errors.New("invalid publicKeyY")
	}
	cVal, err := mustBigFromHex(ch.Challenge)
	if err != nil {
		return "", errors.New("invalid challenge c")
	}

	left := new(big.Int).Exp(s.g, sVal, s.p)
	yc := new(big.Int).Exp(yVal, cVal, s.p)
	right := new(big.Int).Mul(rVal, yc)
	right.Mod(right, s.p)

	if left.Cmp(right) != 0 {
		return "", errors.New("zkp verification failed")
	}
	token, err := s.jwtManager.CreateToken(req.Username)
	if err != nil {
		return "", errors.New("token create failed")
	}
	return token, nil
}
