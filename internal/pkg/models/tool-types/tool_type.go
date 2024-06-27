package users

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type ToolType struct {
	models.Model
	Name        string `gorm:"column:name;" json:"name" form:"name"`
	Description string `gorm:"column:description;" json:"description" form:"description"`
	Url         string `gorm:"column:url;" json:"url" form:"url"`
	ApiKey      string `gorm:"column:api_key;" json:"api_key" form:"api_key"`
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
