package trivy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	models "vulnerability-management/internal/pkg/models/findings"
	tool_models "vulnerability-management/internal/pkg/models/tool-types"

	"github.com/rs/zerolog/log"
)

type Trivy struct{}

func (p *Trivy) Parser(toolInfo tool_models.ToolInfo) ([]models.Finding, error) {
	log.Info().Msgf("Parser Trivy")
	findings, err := getFindings(toolInfo.ReportFile)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, err
	}

	for _, finding := range findings {
		log.Info().Msgf(finding.Title)
	}
	return findings, nil
}

func (p *Trivy) GetToolTypes() string {
	return "Trivy"
}

func (p *Trivy) RequiresFile() bool {
	return true
}

func parseJSON(jsonOutput []byte) ([]interface{}, error) {
	var deserialized interface{}

	// Attempt to deserialize JSON
	err := json.Unmarshal(jsonOutput, &deserialized)
	if err != nil {
		log.Error().Msgf("failed to parse JSON:" + err.Error())
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Check if deserialized object is a list of JSON objects
	if objList, ok := deserialized.([]interface{}); ok {
		return objList, nil
	}

	// If not a list, return as single-element list
	return []interface{}{deserialized}, nil
}

// getFindings parses the scan file and returns a list of findings
func getFindings(filename string) ([]models.Finding, error) {
	jsonFile, err := os.Open(filename)
	if err != nil {
		log.Error().Msgf("Error opening JSON file: %v", err)
	}
	defer jsonFile.Close()

	// Read JSON file
	jsonOutput, err := io.ReadAll(jsonFile)
	if err != nil {
		log.Error().Msgf("Error reading JSON file: %v", err)
	}
	findings := []models.Finding{}

	if jsonOutput != nil {
		deserialized, err := parseJSON(jsonOutput)
		if err != nil {
			return nil, err
		}

		for _, tree := range deserialized {
			if treeMap, ok := tree.(map[string]interface{}); ok {
				artifactType, _ := treeMap["ArtifactType"].(string)

				if results, ok := treeMap["Results"].([]interface{}); ok {
					item := getItems(results, artifactType)
					if item != nil {
						findings = append(findings, item...)
					}

				}

			}
		}
	}

	return findings, nil
}

func getItems(results []interface{}, artifactType string) []models.Finding {
	var items []models.Finding

	for _, targetData := range results {
		if result, ok := targetData.(map[string]interface{}); ok {
			if target, ok := result["Target"].(string); ok {
				targetTarget := result["Target"].(string)
				targetClass := result["Class"].(string)
				targetType := result["Type"].(string)

				vulnerabilities := result["Vulnerabilities"].([]interface{})
				for _, vuln := range vulnerabilities {
					if vulnMap, ok := vuln.(map[string]interface{}); ok {
						vulnID := fmt.Sprintf("%v", vulnMap["VulnerabilityID"])
						packageName := vulnMap["PkgName"].(string)

						severity := vulnMap["Severity"].(string)

						var filePath string
						if targetClass == "os-pkgs" || targetClass == "lang-pkgs" {
							if file, ok := vulnMap["PkgPath"].(string); ok {
								filePath = file
							} else {
								filePath = targetTarget
							}
						} else if targetClass == "config" {
							filePath = targetTarget
						}

						installedVersion := vulnMap["InstalledVersion"].(string)
						references := ""
						if refers, ok := vulnMap["References"].([]interface{}); ok {
							for _, refers := range refers {
								if refer, ok := refers.(string); ok {
									references += refer + "\n"
								}
							}

						}

						mitigation := ""
						if mgt, ok := vulnMap["FixedVersion"].(string); ok {
							mitigation = mgt
						}

						var cwe int

						if cweIDs, ok := vulnMap["CweIDs"].([]interface{}); ok {
							if len(cweIDs) > 0 {
								if cweID, ok := cweIDs[0].(string); ok {
									cwe = parseCweID(cweID)
								}
							}
						} else {
							cwe = 0
						}

						title := fmt.Sprintf("%v %v %v", vulnID, packageName, installedVersion)

						vulTitle := ""
						if titleValue, ok := vulnMap["Title"].(string); ok {
							vulTitle = titleValue
						}
						vulDescription := ""
						if descValue, ok := vulnMap["Description"].(string); ok {
							vulDescription = descValue
						}

						description := fmt.Sprintf("Title: %v\nTarget: %v\nType: %v\nFixed Version: %v\nDescription: %v\n",
							vulTitle,
							target,
							targetType,
							mitigation,
							vulDescription)

						finding := models.Finding{
							Title:          title,
							CWE:            uint64(cwe),
							Severity:       mapSeverity(severity),
							FilePath:       filePath,
							Reference:      references,
							Description:    description,
							Mitigation:     mitigation,
							StaticFinding:  true,
							DynamicFinding: false,
							Active:         true,
							VulnIDFromTool: vulnID,
						}

						items = append(items, finding)
					}
				}
			}
		}
	}

	return items
}

func parseCweID(cweID string) int {
	split := strings.Split(cweID, "-")
	if len(split) > 1 {
		cweNumber, err := strconv.Atoi(split[1])
		if err == nil {
			return cweNumber
		}
	}
	return 0 // return default value if parsing fails
}

func mapSeverity(severity string) uint64 {
	severityMapping := map[string]uint64{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      1,
		"info":     0,
	}
	if val, ok := severityMapping[strings.ToLower(severity)]; ok {
		return val
	}
	log.Printf("Warning: Unknown severity value detected '%s'. Bypass to 'Medium' value", severity)
	return 3
}
