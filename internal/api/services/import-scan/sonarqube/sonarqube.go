package sonarqube

import (
	"fmt"
	"net/http"
	models "vulnerability-management/internal/pkg/models/findings"
	tool_models "vulnerability-management/internal/pkg/models/tool-types"

	"github.com/rs/zerolog/log"
)

type SonarQube struct{}

func (p *SonarQube) Parser(toolInfo tool_models.ToolInfo) ([]models.Finding, error) {
	log.Info().Msgf("Parser SonarQube")
	findings, err := getFindings(toolInfo)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, err
	}

	// for _, finding := range findings {
	// 	log.Info().Msgf(finding.Title)
	// }
	return findings, nil
}

func (p *SonarQube) GetToolTypes() string {
	return "SonarQube"
}

func (p *SonarQube) RequiresFile() bool {
	return false
}

func getFindings(toolInfo tool_models.ToolInfo) ([]models.Finding, error) {
	findings := []models.Finding{}
	client := SonarQubeClient{
		SonarAPIURL: toolInfo.Url,
		// SonarAPIURL: "https://sonarqube.vbeecore.com/api",
		DefaultHeaders: map[string]string{
			// "Authorization": "Bearer " + "squ_1282bb51cee8066cd8ba140d15c10029e0c9d56f",
			"Authorization": "Bearer " + toolInfo.ApiKey,
		},
		Session: &http.Client{},
	}

	// componentKey := "esupport-backend"
	componentKey := toolInfo.ServiceKey
	// types := "VULNERABILITY"
	// types := "BUG"
	// branch := ""

	findings1, err := client.ImportIssues(componentKey)
	if err != nil {
		log.Error().Msgf("Error finding issues: %v", err)
	} else {
		findings = append(findings, findings1...)
	}

	findings2, err := client.ImportHotspots(componentKey)
	if err != nil {
		log.Error().Msgf("Error finding issues: %v", err)
	} else {
		findings = append(findings, findings2...)
	}

	for _, finding := range findings {
		fmt.Println("Hi")
		fmt.Println(finding.Title)
	}
	return findings, nil
}
