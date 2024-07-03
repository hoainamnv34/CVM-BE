package users

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type Project struct {
	models.Model
	Name                 string `gorm:"column:name;" json:"name" form:"name"`
	Description          string `gorm:"column:description;" json:"description" form:"description"`
	ProjectGroupID       uint64 `gorm:"column:project_group_id;" json:"project_group_id" form:"project_group_id"`
	RepositoryURL        string `gorm:"column:repository_url;" json:"repository_url" form:"repository_url"`
	PipelineEvaluationID uint64 `gorm:"column:pipeline_evaluation_id;" json:"pipeline_evaluation_id" form:"pipeline_evaluation_id"`
}

func (m *Project) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()
	return nil
}

func (m *Project) BeforeUpdate() error {
	m.UpdatedAt = time.Now()
	return nil
}
