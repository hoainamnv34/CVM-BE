package users

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type PipelineEvaluation struct {
	models.Model
	SeverityCriticalScore uint64 `gorm:"column:severity_critical_score;" json:"severity_critical_score" form:"severity_critical_score"`
	SeverityHighScore     uint64 `gorm:"column:severity_high_score;" json:"severity_high_score" form:"severity_high_score"`
	SeverityMediumScore   uint64 `gorm:"column:severity_medium_score;" json:"severity_medium_score" form:"severity_medium_score"`
	SeverityLowScore      uint64 `gorm:"column:severity_low_score;" json:"severity_low_score" form:"severity_low_score"`
	ThresholdScore        uint64 `gorm:"column:threshold_score;" json:"threshold_score" form:"threshold_score"`
}

func (m *PipelineEvaluation) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()
	return nil
}

func (m *PipelineEvaluation) BeforeUpdate() error {
	m.UpdatedAt = time.Now()
	return nil
}
