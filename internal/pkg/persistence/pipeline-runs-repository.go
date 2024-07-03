package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/pipeline-runs"
)

type PipelineRunRepository struct{}


var PipelineRunRepo *PipelineRunRepository = &PipelineRunRepository{}

func (r *PipelineRunRepository) Get(id string) (*models.PipelineRun, error) {
	pipelineRun := models.PipelineRun{}

	err := db.DB.Model(&models.PipelineRun{}).Where("id = ?", id).First(&pipelineRun).Error
	if err != nil {
		return nil, err
	}

	return &pipelineRun, err
}

func (r *PipelineRunRepository) Query(where interface{}, offset int, limit int) (*[]models.PipelineRun, int, error) {
	pipelineRuns := []models.PipelineRun{}

	count := 0

	query := db.DB.Model(&models.PipelineRun{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&pipelineRuns).Error
	if err != nil {
		return nil, 0, err
	}

	return &pipelineRuns, count, err
}

func (r *PipelineRunRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.PipelineRun{}).Where(where).Count(&count).Error

	return count, err
}

func (r *PipelineRunRepository) Add(pipelineRun *models.PipelineRun) (*models.PipelineRun, error) {
	err := db.DB.Model(&models.PipelineRun{}).Create(pipelineRun).Error

	return pipelineRun, err
}

func (r *PipelineRunRepository) Update(pipelineRun *models.PipelineRun) error {
	err := db.DB.Model(&models.PipelineRun{}).Save(pipelineRun).Error

	return err
}

func (r *PipelineRunRepository) Delete(pipelineRun *models.PipelineRun) error {
	err := db.DB.Model(&models.PipelineRun{}).Delete(pipelineRun).Error

	return err
}
