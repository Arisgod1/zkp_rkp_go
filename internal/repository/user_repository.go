package repository

import (
	"github.com/Arisgod1/zkp_rkp_go/internal/model"
	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CountByUsername(username string) (int64, error) {
	var count int64
	err := r.db.Model(&model.UserCredentials{}).Where("username = ?",
		username).Count(&count).Error
	return count, err
}
func (r *UserRepository) Create(user *model.UserCredentials) error {
	return r.db.Create(user).Error
}

func (r *UserRepository) FindByUsername(username string) (*model.UserCredentials, error) {
	var user model.UserCredentials
	if err := r.db.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}
