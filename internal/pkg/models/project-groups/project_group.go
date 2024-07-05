package projectgroups

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type ProjectGroup struct {
	models.Model
	Name        string `gorm:"column:name;" json:"name" form:"name"`
	Description string `gorm:"column:description;" json:"description" form:"description"`
}

func (m *ProjectGroup) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()
	return nil
}

func (m *ProjectGroup) BeforeUpdate() error {
	m.UpdatedAt = time.Now()
	return nil
}
