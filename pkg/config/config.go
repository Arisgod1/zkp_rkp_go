package config

import (
	"github.com/spf13/viper"
)

type KafkaConfig struct {
	Enabled        bool     `mapstructure:"enabled"`
	Brokers        []string `mapstructure:"brokers"`
	Topic          string   `mapstructure:"topic"`
	ClientID       string   `mapstructure:"client_id"`
	AsyncQueueSize int      `mapstructure:"async_queue_size"`
	WriteTimeoutMs int      `mapstructure:"write_timeout_ms"`
}
type Config struct {
	App struct {
		Host string `mapstructure:"host"`
		Port string `mapstructure:"port"`
	} `mapstructure:"app"`

	DB struct {
		DSN string `mapstructure:"dsn"`
	} `mapstructure:"db"`

	Redis struct {
		Addr string `mapstructure:"addr"`
	} `mapstructure:"redis"`

	JWT struct {
		Secret        string `mapstructure:"secret"`
		ExpireSeconds int64  `mapstructure:"expire_seconds"`
	} `mapstructure:"jwt"`

	ZKP struct {
		ChallengeTTLSeconds int `mapstructure:"challenge_ttl_seconds"`
	} `mapstructure:"zkp"`

	RateLimit struct {
		RegisterPerMinute  int `mapstructure:"register_per_minute"`
		ChallengePerMinute int `mapstructure:"challenge_per_minute"`
		VerifyPerMinute    int `mapstructure:"verify_per_minute"`
		BucketCapacity     int `mapstructure:"bucket_capacity"`
		BucketRefillPerSec int `mapstructure:"bucket_refill_per_sec"`
	} `mapstructure:"rate_limit"`

	Kafka KafkaConfig `mapstructure:"kafka"`
}

func MustLoad() *Config {
	viper.SetConfigName("application")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		panic(err)
	}
	return &cfg
}
