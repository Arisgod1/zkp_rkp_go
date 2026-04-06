package model

import "time"

type UserCredentials struct {
	ID         uint   `gorm:"primaryKey"`
	Username   string `gorm:"type:text;not null"`
	PublicKeyY string `gorm:"type:text;not null"`
	Salt       string `gorm:"type:text;not null"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
