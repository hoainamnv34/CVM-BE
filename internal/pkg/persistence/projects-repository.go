package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/projects"
)

type ProjectRepository struct{}

var ProjectRepo *ProjectRepository = &ProjectRepository{}

func (r *ProjectRepository) Get(id string) (*models.Project, error) {
	project := models.Project{}

	err := db.DB.Model(&models.Project{}).Where("id = ?", id).First(&project).Error
	if err != nil {
		return nil, err
	}

	return &project, err
}

func (r *ProjectRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.Project{}).Where(where).Count(&count).Error

	return count, err
}

func (r *ProjectRepository) Query(where interface{}, offset int, limit int) (*[]models.Project, int, error) {
	projects := []models.Project{}

	count := 0

	query := db.DB.Model(&models.Project{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&projects).Error
	if err != nil {
		return nil, 0, err
	}

	return &projects, count, err
}

func (r *ProjectRepository) Add(project *models.Project) (*models.Project, error) {
	err := db.DB.Model(&models.Project{}).Create(project).Error

	return project, err
}

func (r *ProjectRepository) Update(project *models.Project) error {
	err := db.DB.Model(&models.Project{}).Save(project).Error

	return err
}

func (r *ProjectRepository) Delete(project *models.Project) error {
	err := db.DB.Model(&models.Project{}).Delete(project).Error

	return err
}
