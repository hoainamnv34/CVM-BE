package importscan

import (
	models "vulnerability-management/internal/pkg/models/findings"
)

type Tool interface {
	Parser(filename string, servicekey string) ([]models.Finding, error)
	GetToolTypes() string
	RequiresFile() bool
}
