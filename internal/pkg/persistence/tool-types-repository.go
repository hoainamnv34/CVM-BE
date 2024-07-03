package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/tool-types"
)

type ToolTypeRepository struct{}


var ToolTypeRepo *ToolTypeRepository = &ToolTypeRepository{}

func (r *ToolTypeRepository) Get(id string) (*models.ToolType, error) {
	toolType := models.ToolType{}

	err := db.DB.Model(&models.ToolType{}).Where("id = ?", id).First(&toolType).Error
	if err != nil {
		return nil, err
	}

	return &toolType, err
}

func (r *ToolTypeRepository) Query(where interface{}, offset int, limit int) (*[]models.ToolType, int, error) {
	toolTypes := []models.ToolType{}

	count := 0

	query := db.DB.Model(&models.ToolType{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&toolTypes).Error
	if err != nil {
		return nil, 0, err
	}

	return &toolTypes, count, err
}

func (r *ToolTypeRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.ToolType{}).Where(where).Count(&count).Error

	return count, err
}

func (r *ToolTypeRepository) Add(toolType *models.ToolType) (*models.ToolType, error) {
	err := db.DB.Model(&models.ToolType{}).Create(toolType).Error

	return toolType, err
}

func (r *ToolTypeRepository) Update(toolType *models.ToolType) error {
	err := db.DB.Model(&models.ToolType{}).Save(toolType).Error

	return err
}

func (r *ToolTypeRepository) Delete(toolType *models.ToolType) error {
	err := db.DB.Model(&models.ToolType{}).Delete(toolType).Error

	return err
}
