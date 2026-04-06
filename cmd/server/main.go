package main

import (
	"context"
	"errors"
	"math/big"

	"github.com/Arisgod1/zkp_rkp_go/internal/auth"
	"github.com/Arisgod1/zkp_rkp_go/internal/controller"
	"github.com/Arisgod1/zkp_rkp_go/internal/middleware"
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
	// 1) 初始化基础设施（DB / Redis）
	dsn := "host=localhost user=postgres password=postgres dbname=zkp_auth port=5432 sslmode=disable TimeZone=Asia/Shanghai"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	if err := db.AutoMigrate(&model.UserCredentials{}); err != nil {
		panic(err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
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
	jwtManager := auth.NewJWTManager("replace-this-with-env-secret-in-prod", 86400)
	userRepo := repository.NewUserRepository(db)
	authSvc := service.NewAuthService(userRepo, rdb, jwtManager, p, q, g)
	authCtl := controller.NewAuthController(authSvc)
	userCtl := controller.NewUserController()
	// 4) 注册路由
	r := gin.Default()
	api := r.Group("/api/v1")
	{
		r.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "pong"})
		})
		authGroup := api.Group("/auth")
		{
			authGroup.POST("/register", authCtl.Register)
			authGroup.POST("/challenge", authCtl.Challenge)
			authGroup.POST("/verify", authCtl.Verify)
		}
		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(jwtManager))
		{
			protected.GET("me", userCtl.Me)
		}
	}
	// 5) 启动
	if err := r.Run("localhost:8080"); err != nil {
		panic(err)
	}
}
