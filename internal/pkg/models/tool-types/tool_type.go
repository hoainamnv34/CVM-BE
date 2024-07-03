package users

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type ToolType struct {
	models.Model
	Name        string `gorm:"column:name;" json:"name" form:"name"`
	Description string `gorm:"column:description;" json:"description" form:"description"`
}

func (m *ToolType) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()
	return nil
}

func (m *ToolType) BeforeUpdate() error {
	m.UpdatedAt = time.Now()
	return nil
}
