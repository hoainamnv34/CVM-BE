package users

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type PipelineRun struct {
	models.Model
	BranchName           string `gorm:"column:branch_name;" json:"branch_name" form:"branch_name"`
	CommitHash           string `gorm:"column:commit_hash;" json:"commit_hash" form:"commit_hash"`
	Status               uint64 `gorm:"column:status;" json:"status" form:"status"`
	ProjectID            uint64 `gorm:"column:project_id;" json:"project_id" form:"project_id"`
	PipelineRunURL       string `gorm:"column:pipeline_run_url;" json:"pipeline_run_url" form:"pipeline_run_url"`
	PipelineRunID        uint64 `gorm:"column:pipeline_run_id;" json:"pipeline_run_id" form:"pipeline_run_id"`
}

func (m *PipelineRun) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()

	return nil
}

func (m *PipelineRun) BeforeUpdate() error {
	m.UpdatedAt = time.Now()

	return nil
}
