package main

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/Arisgod1/zkp_rkp_go/internal/auth"
	"github.com/Arisgod1/zkp_rkp_go/internal/controller"
	"github.com/Arisgod1/zkp_rkp_go/internal/middleware"
	"github.com/Arisgod1/zkp_rkp_go/pkg/config"
	"github.com/Arisgod1/zkp_rkp_go/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/Arisgod1/zkp_rkp_go/internal/model"
	"github.com/Arisgod1/zkp_rkp_go/internal/repository"
	"github.com/Arisgod1/zkp_rkp_go/internal/service"
)

const pHex1536 = "" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"

func mustBigFromHex(h string) *big.Int {
	n := new(big.Int)
	_, ok := n.SetString(h, 16)
	if !ok {
		panic(errors.New("invalid hex"))
	}
	return n
}

func main() {
	//导入配置文件
	cfg := config.MustLoad()

	// 1) 初始化基础设施（DB / Redis）
	db, err := gorm.Open(postgres.Open(cfg.DB.DSN), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	if err := db.AutoMigrate(&model.UserCredentials{}); err != nil {
		panic(err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr})
	// 启动前探活
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		panic(err)
	}

	// 2) 初始化群参数（一次性）
	p := mustBigFromHex(pHex1536)
	q := new(big.Int).Sub(p, big.NewInt(1))
	q.Div(q, big.NewInt(2))
	g := big.NewInt(2)

	// 3) 组装依赖（依赖注入）
	jwtManager := auth.NewJWTManager(cfg.JWT.Secret, cfg.JWT.ExpireSeconds)
	userRepo := repository.NewUserRepository(db)
	challengeTTL := time.Duration(cfg.ZKP.ChallengeTTLSeconds) * time.Second
	authSvc := service.NewAuthService(userRepo, rdb, jwtManager, p, q, g, challengeTTL)
	authCtl := controller.NewAuthController(authSvc)
	userCtl := controller.NewUserController()
	// 4) 注册路由
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.RequestIDMiddleware())
	log := logger.MustNew()
	r.Use(middleware.LoggingMiddleware(log))
	api := r.Group("/api/v1")
	{
		r.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "pong"})
		})
		authGroup := api.Group("/auth")
		{
			ctx := context.Background()

			authGroup.POST("/register",
				middleware.RateLimitMiddleware(rdb, ctx, "zkp:ratelimit:register", cfg.RateLimit.RegisterPerMinute, time.Minute),
				authCtl.Register,
			)
			authGroup.POST("/challenge",
				middleware.RateLimitMiddleware(rdb, ctx, "zkp:ratelimit:challenge", cfg.RateLimit.ChallengePerMinute, time.Minute),
				authCtl.Challenge,
			)
			authGroup.POST("/verify",
				middleware.RateLimitMiddleware(rdb, ctx, "zkp:ratelimit:verify", cfg.RateLimit.VerifyPerMinute, time.Minute),
				authCtl.Verify,
			)
		}
		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(jwtManager))
		{
			protected.GET("me", userCtl.Me)
		}
	}
	// 5) 启动
	if err := r.Run("localhost:" + cfg.App.Port); err != nil {
		panic(err)
	}
}
