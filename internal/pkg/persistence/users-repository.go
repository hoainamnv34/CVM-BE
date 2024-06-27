package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/users"
)

type UserRepository struct{}

var UserRepo *UserRepository = &UserRepository{}

func (r *UserRepository) Get(id string) (*models.User, error) {
	user := models.User{}

	err := db.DB.Model(&models.User{}).Where("id = ?", id).First(&user).Error
	if err != nil {
		return nil, err
	}

	return &user, err
}

func (r *UserRepository) Query(where interface{}, offset int, limit int) (*[]models.User, int, error) {
	users := []models.User{}

	count := 0

	query := db.DB.Model(&models.User{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&users).Error
	if err != nil {
		return nil, 0, err
	}

	return &users, count, err
}

func (r *UserRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.User{}).Where(where).Count(&count).Error

	return count, err
}

func (r *UserRepository) Add(user *models.User) (*models.User, error) {
	err := db.DB.Model(&models.User{}).Create(user).Error

	return user, err
}

func (r *UserRepository) Update(user *models.User) error {
	err := db.DB.Model(&models.User{}).Save(user).Error

	return err
}

func (r *UserRepository) Delete(user *models.User) error {
	err := db.DB.Model(&models.User{}).Delete(user).Error

	return err
}
