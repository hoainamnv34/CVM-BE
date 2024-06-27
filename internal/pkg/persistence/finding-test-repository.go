package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/finding-test"
)

type FindingTestRepository struct{}

var FindingTestRepo *FindingTestRepository = &FindingTestRepository{}

func (r *FindingTestRepository) Get(id string) (*models.FindingTest, error) {
	findingTest := models.FindingTest{}

	err := db.DB.Model(&models.FindingTest{}).Where("id = ?", id).First(&findingTest).Error
	if err != nil {
		return nil, err
	}

	return &findingTest, err
}

func (r *FindingTestRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.FindingTest{}).Where(where).Count(&count).Error

	return count, err
}

func (r *FindingTestRepository) Query(where interface{}, offset int, limit int) (*[]models.FindingTest, int, error) {
	findingtests := []models.FindingTest{}

	count := 0

	query := db.DB.Model(&models.FindingTest{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&findingtests).Error
	if err != nil {
		return nil, 0, err
	}

	return &findingtests, count, err
}

func (r *FindingTestRepository) Add(findingtest *models.FindingTest) (*models.FindingTest, error) {
	err := db.DB.Model(&models.FindingTest{}).Create(findingtest).Error

	return findingtest, err
}

func (r *FindingTestRepository) Update(findingtest *models.FindingTest) error {
	err := db.DB.Model(&models.FindingTest{}).Save(findingtest).Error

	return err
}

func (r *FindingTestRepository) Delete(findingtest *models.FindingTest) error {
	err := db.DB.Model(&models.FindingTest{}).Delete(findingtest).Error

	return err
}
