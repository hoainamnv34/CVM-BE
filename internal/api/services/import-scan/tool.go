package importscan

import (
	models "vulnerability-management/internal/pkg/models/findings"
	tool_models "vulnerability-management/internal/pkg/models/tool-types"
)

type Tool interface {
	Parser(toolInfo tool_models.ToolInfo) ([]models.Finding, error)
	GetToolTypes() string
	RequiresFile() bool
}
