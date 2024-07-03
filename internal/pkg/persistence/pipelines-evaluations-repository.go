package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/pipeline-evaluations"
)

type PipelineEvaluationRepository struct{}


var PipelineEvaluationRepo *PipelineEvaluationRepository = &PipelineEvaluationRepository{}

func (r *PipelineEvaluationRepository) Get(id string) (*models.PipelineEvaluation, error) {
	pipelineEvaluation := models.PipelineEvaluation{}

	err := db.DB.Model(&models.PipelineEvaluation{}).Where("id = ?", id).First(&pipelineEvaluation).Error
	if err != nil {
		return nil, err
	}

	return &pipelineEvaluation, err
}

func (r *PipelineEvaluationRepository) Query(where interface{}, offset int, limit int) (*[]models.PipelineEvaluation, int, error) {
	pipelineEvaluations := []models.PipelineEvaluation{}

	count := 0

	query := db.DB.Model(&models.PipelineEvaluation{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&pipelineEvaluations).Error
	if err != nil {
		return nil, 0, err
	}

	return &pipelineEvaluations, count, err
}

func (r *PipelineEvaluationRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.PipelineEvaluation{}).Where(where).Count(&count).Error

	return count, err
}

func (r *PipelineEvaluationRepository) Add(pipelineEvaluation *models.PipelineEvaluation) (*models.PipelineEvaluation, error) {

	err := db.DB.Model(&models.PipelineEvaluation{}).Create(pipelineEvaluation).Error

	return pipelineEvaluation, err
}

func (r *PipelineEvaluationRepository) Update(pipelineEvaluation *models.PipelineEvaluation) error {
	err := db.DB.Model(&models.PipelineEvaluation{}).Save(pipelineEvaluation).Error

	return err
}

func (r *PipelineEvaluationRepository) Delete(pipelineEvaluation *models.PipelineEvaluation) error {
	err := db.DB.Model(&models.PipelineEvaluation{}).Delete(pipelineEvaluation).Error

	return err
}
