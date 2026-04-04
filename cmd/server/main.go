package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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

		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate challenge"})
			return
		}
		challengeHex := hex.EncodeToString(buf)
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
		// 先返回固定群参数占位（下一课替换成真实参数）
		pHex := "ffffffffffffffff" // 占位
		qHex := "7fffffffffffffff" // 占位
		gHex := "2"

		//用户不存在也返回正常结构，防用户名枚举
		_ = userExists
		c.JSON(http.StatusOK, gin.H{
			"challengeId": challengeID,
			"c":           challengeHex,
			"p":           pHex,
			"q":           qHex,
			"g":           gHex,
		})
	})
	err = r.Run(":8080")
	if err != nil {
		return
	}
}
