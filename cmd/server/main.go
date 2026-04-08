package main

import (
	"context"
	"errors"
	stdlog "log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Arisgod1/zkp_rkp_go/internal/audit"
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

func buildAuditPublisher(cfg *config.Config) (audit.Publisher, func()) {
	if !cfg.Kafka.Enabled {
		return audit.NewNoopPublisher(), func() {}
	}

	brokers := cfg.Kafka.Brokers
	topic := strings.TrimSpace(cfg.Kafka.Topic)
	if len(brokers) == 0 || topic == "" {
		panic("kafka.enabled=true but kafka.topic is empty")
	}

	clientID := strings.TrimSpace(cfg.Kafka.ClientID)
	if clientID == "" {
		clientID = "zkp_rkp_go"
	}

	writeTimeout := time.Duration(cfg.Kafka.WriteTimeoutMs) * time.Millisecond
	if writeTimeout <= 0 {
		writeTimeout = 800 * time.Millisecond
	}
	queueSize := cfg.Kafka.AsyncQueueSize
	if queueSize <= 0 {
		queueSize = 1000
	}

	kafkaPublisher := audit.NewKafkaPublisher(audit.KafkaPublisherConfig{
		Brokers:      brokers,
		Topic:        topic,
		ClientID:     clientID,
		WriteTimeout: writeTimeout,
	})
	asyncPublisher := audit.NewAsyncPublisher(kafkaPublisher, queueSize, writeTimeout)

	closeFn := func() {
		asyncPublisher.Close()
		if err := kafkaPublisher.Close(); err != nil {
			stdlog.Printf("[audit] close kafka writer failed: %v", err)
		}
	}

	return asyncPublisher, closeFn
}

func main() {
	//导入配置文件
	cfg := config.MustLoad()

	// 1) 初始化基础设施（DB / Redis）
	db, err := gorm.Open(postgres.Open(cfg.DB.DSN), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := sqlDB.Close(); err != nil {
			stdlog.Printf("[db] close failed: %v", err)
		}
	}()

	if err := db.AutoMigrate(&model.UserCredentials{}); err != nil {
		panic(err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: cfg.Redis.Addr})
	// 启动前探活
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		panic(err)
	}
	defer func() {
		if err := rdb.Close(); err != nil {
			stdlog.Printf("[redis] close failed: %v", err)
		}
	}()

	// 2) 初始化群参数（一次性）
	p := mustBigFromHex(pHex1536)
	q := new(big.Int).Sub(p, big.NewInt(1))
	q.Div(q, big.NewInt(2))
	g := big.NewInt(2)

	// 3) 组装依赖（依赖注入）
	jwtManager := auth.NewJWTManager(cfg.JWT.Secret, cfg.JWT.ExpireSeconds)
	userRepo := repository.NewUserRepository(db)
	challengeTTL := time.Duration(cfg.ZKP.ChallengeTTLSeconds) * time.Second
	auditPublisher, closeAudit := buildAuditPublisher(cfg)
	defer closeAudit()
	authService := service.NewAuthService(userRepo, rdb, jwtManager, p, q, g, challengeTTL, auditPublisher)
	authCtl := controller.NewAuthController(authService)
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
	serverHost := strings.TrimSpace(cfg.App.Host)
	if serverHost == "" {
		serverHost = "0.0.0.0"
	}
	serverAddr := net.JoinHostPort(serverHost, cfg.App.Port)
	srv := &http.Server{
		Addr:    serverAddr,
		Handler: r,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	case <-sigCtx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}
