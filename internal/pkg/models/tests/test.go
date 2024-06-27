package users

import (
	"time"

	"vulnerability-management/internal/pkg/models"
)

type Test struct {
	models.Model
	Name          string `gorm:"column:name;" json:"name" form:"name"`
	PipelineRunID uint64 `gorm:"column:pipeline_run_id;" json:"pipeline_run_id" form:"pipeline_run_id"`
	ToolTypeID    uint64 `gorm:"column:tool_type_id;" json:"tool_type_id" form:"tool_type_id"`
}

func (m *Test) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()

	return nil
}

func (m *Test) BeforeUpdate() error {
	m.UpdatedAt = time.Now()

	return nil
}
