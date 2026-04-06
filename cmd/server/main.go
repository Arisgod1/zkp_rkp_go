package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type RegisterRequest struct {
	Username   string `json:"username"`
	PublicKeyY string `json:"publicKeyY"`
	Salt       string `json:"salt"`
}

type UserCredentials struct {
	ID         uint   `gorm:"primaryKey"`
	Username   string `gorm:"type:text;not null"`
	PublicKeyY string `gorm:"type:text;not null"`
	Salt       string `gorm:"type:text;not null"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
type ChallengeRequest struct {
	Username string `json:"username"`
	ClientR  string `json:"clientR"`
}
type ChallengeCache struct {
	Username  string `json:"username"`
	ClientR   string `json:"clientR"`
	Challenge string `json:"challenge"`
	CreatedAt int64  `json:"createdAt"`
}
type VerifyRequest struct {
	ChallengeID string `json:"challengeId"`
	S           string `json:"s"`
	ClientR     string `json:"clientR"`
	Username    string `json:"username"`
}

const pHex1536 = "" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"

const gHex1536 = "2"

func mustGroupParams() (p, q, g *big.Int) {
	p, err := mustBigFromHex(pHex1536)
	if err != nil {
		panic(err)
	}
	g, err = mustBigFromHex(gHex1536)
	if err != nil {
		panic(err)
	}
	one := big.NewInt(1)
	q = new(big.Int).Sub(p, one)
	q.Div(q, big.NewInt(2)) // q = (p-1)/2
	return
}

func mustBigFromHex(h string) (*big.Int, error) {
	n := new(big.Int)
	_, ok := n.SetString(h, 16)
	if !ok {
		return nil, errors.New("invalid hex big integer")
	}
	return n, nil
}

func computeChallengeHex(clientRHex, publicYHex, username string) string {
	raw := clientRHex + "|" + publicYHex + "|" + username
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func modExp(base, exp, mod *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, mod)
}

// 临时结构体
type DevProofRequest struct {
	Username string `json:"username"`
}

// 临时工具函数生成 [1, q-1] 随机数
func randInRange(max *big.Int) (*big.Int, error) {
	// 返回 [1, max-1]
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return n, nil
}
func main() {
	// PostgreSQL
	dsn := "host=localhost user=postgres password=postgres dbname=zkp_auth port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	if err := db.AutoMigrate(&UserCredentials{}); err != nil {
		panic(err)
	}
	// Redis
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		panic(err)
	}

	p, q, g := mustGroupParams()
	_ = q

	r := gin.Default()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	r.POST("/api/v1/auth/register", func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
			return
		}
		if req.Username == "" || req.PublicKeyY == "" || req.Salt == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username/publicKeyY/salt cannot be empty"})
			return
		}
		var count int64
		if err := db.Model(&UserCredentials{}).Where("username = ?", req.Username).Count(&count).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed"})
			return
		}
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username already exists"})
			return
		}
		user := UserCredentials{
			Username:   req.Username,
			PublicKeyY: req.PublicKeyY,
			Salt:       req.Salt,
		}
		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("db insert failed").Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"username": req.Username,
			"message":  "User registered successfully",
		})
	})

	r.POST("/api/v1/auth/challenge", func(c *gin.Context) {
		var req ChallengeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username/clientR cannot be empty"})
			return
		}
		var user UserCredentials
		err := db.Where("username = ?", req.Username).First(&user).Error
		userExists := err == nil

		challengeID := uuid.NewString()
		var challengeHex string
		if userExists {
			challengeHex = computeChallengeHex(req.ClientR, user.PublicKeyY, req.Username)
		} else {
			fakeY := "0000000000000000000000000000000000000000000000000000000000000000"
			challengeHex = computeChallengeHex(req.ClientR, fakeY, req.Username)
		}
		//防枚举:即使用户不存在,也照样存一个"假挑战"
		cache := ChallengeCache{
			Username:  req.Username,
			ClientR:   req.ClientR,
			Challenge: challengeHex,
			CreatedAt: time.Now().Unix(),
		}
		raw, _ := json.Marshal(cache)

		redisKey := "zkp:challenge:" + challengeID
		if err := rdb.Set(ctx, redisKey, raw, 300*time.Second).Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to cache challenge"})
			return
		}

		//用户不存在也返回正常结构，防用户名枚举
		_ = userExists
		c.JSON(http.StatusOK, gin.H{
			"challengeId": challengeID,
			"c":           challengeHex,
			"p":           p.Text(16),
			"q":           q.Text(16),
			"g":           g.Text(16),
		})
	})
	r.POST("/api/v1/auth/verify", func(c *gin.Context) {
		var req VerifyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
			return
		}
		if req.ChallengeID == "" || req.S == "" || req.ClientR == "" || req.Username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "challengeId/s/clientR/username cannot be empty"})
			return
		}
		//查redis的challenge
		redisKey := "zkp:challenge:" + req.ChallengeID
		raw, err := rdb.Get(ctx, redisKey).Result()
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "challenge not found or expired"})
			return
		}

		var ch ChallengeCache
		if err := json.Unmarshal([]byte(raw), &ch); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "challenge parse failed"})
			return
		}
		if ch.Username != req.Username || ch.ClientR != req.ClientR {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "challenge mismatch"})
			return
		}
		//查公钥
		var user UserCredentials
		if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credential"})
			return
		}
		//重新计算c
		recomputedCHex := computeChallengeHex(req.ClientR, user.PublicKeyY, req.Username)
		if recomputedCHex != ch.Challenge {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "challenge invalid"})
			return
		}
		// ===== 先用当前占位群参数（下节替换成 RFC 1536-bit）=====
		p, q, g := mustGroupParams()
		_ = q
		sVal, err := mustBigFromHex(req.S)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid s"})
			return
		}
		rVal, err := mustBigFromHex(req.ClientR)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid clientR"})
			return
		}
		yVal, err := mustBigFromHex(user.PublicKeyY)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid publicKeyY"})
			return
		}
		cVal, err := mustBigFromHex(ch.Challenge)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid challenge c"})
			return
		}
		left := modExp(g, sVal, p)
		yc := modExp(yVal, cVal, p)
		right := new(big.Int).Mul(rVal, yc)
		right.Mod(right, p)
		if left.Cmp(right) != 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "zkp verification failed"})
			_ = rdb.Del(ctx, redisKey).Err()
			return
		}
		_ = rdb.Del(ctx, redisKey).Err()

		c.JSON(http.StatusOK, gin.H{
			"token":     "demo-jwt-token-next-step",
			"type":      "Bearer",
			"expiresIn": 86400,
		})
	})
	//dev测试接口
	r.POST("/dev/proof", func(c *gin.Context) {
		var req DevProofRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username required"})
			return
		}

		// 1) 生成私钥 x 与公钥 Y
		x, err := randInRange(q)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "x gen failed"})
			return
		}
		Y := modExp(g, x, p)

		// 2) 注册
		regBody := RegisterRequest{
			Username:   req.Username,
			PublicKeyY: Y.Text(16),
			Salt:       "dev-salt",
		}
		_ = regBody
		// 如果已存在就忽略
		var count int64
		_ = db.Model(&UserCredentials{}).Where("username = ?", req.Username).Count(&count).Error
		if count == 0 {
			// create
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username exists in dev, use a new username"})
			return
		}

		// 3) 生成 r, R
		rnd, err := randInRange(q)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "r gen failed"})
			return
		}
		R := modExp(g, rnd, p)

		// 4) 计算 c = H(R||Y||username)
		cHex := computeChallengeHex(R.Text(16), Y.Text(16), req.Username)
		cVal, err := mustBigFromHex(cHex)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "c parse failed"})
			return
		}

		// 5) s = r + c*x mod q
		cx := new(big.Int).Mul(cVal, x)
		s := new(big.Int).Add(rnd, cx)
		s.Mod(s, q)

		c.JSON(http.StatusOK, gin.H{
			"username": req.Username,
			"x":        x.Text(16), // 仅dev演示
			"publicY":  Y.Text(16),
			"clientR":  R.Text(16),
			"c":        cHex,
			"s":        s.Text(16),
		})
	})

	err = r.Run(":8080")
	if err != nil {
		return
	}
}
