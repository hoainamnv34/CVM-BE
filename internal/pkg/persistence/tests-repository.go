package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/tests"
)

type TestRepository struct{}


var TestRepo *TestRepository = &TestRepository{}

func (r *TestRepository) Get(id string) (*models.Test, error) {
	test := models.Test{}

	err := db.DB.Model(&models.Test{}).Where("id = ?", id).First(&test).Error
	if err != nil {
		return nil, err
	}

	return &test, err
}

func (r *TestRepository) Query(where interface{}, offset int, limit int) (*[]models.Test, int, error) {
	tests := []models.Test{}

	count := 0

	query := db.DB.Model(&models.Test{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&tests).Error
	if err != nil {
		return nil, 0, err
	}

	return &tests, count, err
}

func (r *TestRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.Test{}).Where(where).Count(&count).Error

	return count, err
}

func (r *TestRepository) Add(test *models.Test) (*models.Test, error) {
	err := db.DB.Model(&models.Test{}).Create(test).Error

	return test, err
}

func (r *TestRepository) Update(test *models.Test) error {
	err := db.DB.Model(&models.Test{}).Save(test).Error

	return err
}

func (r *TestRepository) Delete(test *models.Test) error {
	err := db.DB.Model(&models.Test{}).Delete(test).Error

	return err
}
