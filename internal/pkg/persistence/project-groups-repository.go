package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/project-groups"
)

type ProjectGroupRepository struct{}

var ProjectGroupRepo *ProjectGroupRepository = &ProjectGroupRepository{}

func (r *ProjectGroupRepository) Get(id string) (*models.ProjectGroup, error) {
	projectGroup := models.ProjectGroup{}

	err := db.DB.Model(&models.ProjectGroup{}).Where("id = ?", id).First(&projectGroup).Error
	if err != nil {
		return nil, err
	}

	return &projectGroup, err
}

func (r *ProjectGroupRepository) Query(where interface{}, offset int, limit int) (*[]models.ProjectGroup, int, error) {
	projectGroups := []models.ProjectGroup{}

	count := 0

	query := db.DB.Model(&models.ProjectGroup{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&projectGroups).Error
	if err != nil {
		return nil, 0, err
	}

	return &projectGroups, count, err
}

func (r *ProjectGroupRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.ProjectGroup{}).Where(where).Count(&count).Error

	return count, err
}

func (r *ProjectGroupRepository) Add(projectGroup *models.ProjectGroup) (*models.ProjectGroup, error) {
	err := db.DB.Model(&models.ProjectGroup{}).Create(projectGroup).Error

	return projectGroup, err
}

func (r *ProjectGroupRepository) Update(projectGroup *models.ProjectGroup) error {
	err := db.DB.Model(&models.ProjectGroup{}).Save(projectGroup).Error

	return err
}

func (r *ProjectGroupRepository) Delete(projectGroup *models.ProjectGroup) error {
	err := db.DB.Model(&models.ProjectGroup{}).Delete(projectGroup).Error

	return err
}
