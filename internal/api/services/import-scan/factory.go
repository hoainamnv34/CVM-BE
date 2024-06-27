package importscan

import (
	"vulnerability-management/internal/api/services/import-scan/checkov"
	dependencycheck "vulnerability-management/internal/api/services/import-scan/dependency-check"
	"vulnerability-management/internal/api/services/import-scan/gitleaks"
	"vulnerability-management/internal/api/services/import-scan/sonarqube"
	"vulnerability-management/internal/api/services/import-scan/trivy"
	"vulnerability-management/internal/api/services/import-scan/zap"
)

type Factory struct {
}

func (f *Factory) CreateTool(toolType string) Tool {
	switch toolType {
	case "Zap":
		return &zap.Zap{}
	case "SonarQube":
		return &sonarqube.SonarQube{}
	case "Gitleaks":
		return &gitleaks.GitLeaks{}
	case "DependencyCheck":
		return &dependencycheck.DependencyCheck{}
	case "Checkov":
		return &checkov.Checkov{}
	case "Trivy":
		return &trivy.Trivy{}
	default:
		return nil
	}
}
