package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type UserCredentials struct {
	ID         uint   `gorm:"primaryKey"`
	Username   string `gorm:"uniqueIndex;size:64;not null"`
	PublicKeyY string `gorm:"type:text;not null"`
	Salt       string `gorm:"type:text;not null"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type RegisterRequest struct {
	Username   string `json:"username"`
	PublicKeyY string `json:"publicKeyY"`
	Salt       string `json:"salt"`
}

func main() {
	// 1) 连接数据库
	dsn := "host=localhost user=postgres password=postgres dbname=zkp_auth port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	// 2) 自动建表
	if err := db.AutoMigrate(&UserCredentials{}); err != nil {
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

		// 3) 检查用户名是否已存在
		var count int64
		if err := db.Model(&UserCredentials{}).
			Where("username = ?", req.Username).
			Count(&count).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db query failed"})
			return
		}
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "username already exists"})
			return
		}

		// 4) 写入数据库
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

	r.Run(":8080")
}
