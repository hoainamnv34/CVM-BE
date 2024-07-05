package pipelineruns

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type PipelineRun struct {
	models.Model
	BranchName string `gorm:"column:branch_name;" json:"branch_name" form:"branch_name"`
	CommitHash string `gorm:"column:commit_hash;" json:"commit_hash" form:"commit_hash"`
	ProjectID  uint64 `gorm:"column:project_id;" json:"project_id" form:"project_id"`
	Status     uint64 `gorm:"column:status;" json:"status" form:"status"`
	RunURL     string `gorm:"column:run_url;" json:"run_url" form:"run_url"`
	RunID      uint64 `gorm:"column:run_id;" json:"run_id" form:"run_id"`
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
