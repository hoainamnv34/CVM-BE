package users

import (
	"time"
	"vulnerability-management/internal/pkg/models"
)

type Finding struct {
	models.Model
	ProjectID        uint64 `gorm:"column:project_id;" json:"project_id" form:"project_id"`
	Title            string `gorm:"column:title;" json:"title" form:"title"`
	RiskDescription  string `gorm:"column:risk_description;" json:"risk_description" form:"risk_description"`
	Severity         uint64 `gorm:"column:severity;" json:"severity" form:"severity"`
	CWE              uint64 `gorm:"column:cwe;" json:"cwe" form:"cwe"`
	Line             uint64 `gorm:"column:line;" json:"line" form:"line"`
	FilePath         string `gorm:"column:file_path;" json:"file_path" form:"file_path"`
	VulnIDFromTool   string `gorm:"column:vuln_id_from_tool;" json:"vuln_id_from_tool" form:"vuln_id_from_tool"`
	UniqueIDFromTool string `gorm:"column:unique_id_from_tool;" json:"unique_id_from_tool" form:"unique_id_from_tool"`
	Mitigation       string `gorm:"column:mitigation;" json:"mitigation" form:"mitigation"`
	Impact           string `gorm:"column:impact;" json:"impact" form:"impact"`
	Reference        string `gorm:"column:reference;" json:"reference" form:"reference"`
	Active           bool   `gorm:"column:active;" json:"active" form:"active"`
	DynamicFinding   bool   `gorm:"column:dynamic_finding;" json:"dynamic_finding" form:"dynamic_finding"`
	Duplicate        bool   `gorm:"column:duplicate;" json:"duplicate" form:"duplicate"`
	RiskAccepted     bool   `gorm:"column:risk_accepted;" json:"risk_accepted" form:"risk_accepted"`
	StaticFinding    bool   `gorm:"column:static_finding;" json:"static_finding" form:"static_finding"`
}

func (m *Finding) BeforeCreate() error {
	m.CreatedAt = time.Now()
	m.UpdatedAt = time.Now()

	return nil
}

func (m *Finding) BeforeUpdate() error {
	m.UpdatedAt = time.Now()

	return nil
}
