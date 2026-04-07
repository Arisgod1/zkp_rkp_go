package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	App struct {
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
	} `mapstructure:"rate_limit"`
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
