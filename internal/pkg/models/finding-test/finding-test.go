package users

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type FindingTest struct {
	models.Model
	TestID    uint64 `gorm:"column:test_id;" json:"test_id" form:"test_id"`
	FindingID uint64 `gorm:"column:finding_id;" json:"finding_id" form:"finding_id"`
}

func (m *FindingTest) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()
	return nil
}

func (m *FindingTest) BeforeUpdate() error {
	m.UpdatedAt = time.Now()
	return nil
}
