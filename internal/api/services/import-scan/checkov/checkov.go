package checkov

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	models "vulnerability-management/internal/pkg/models/findings"

	"github.com/rs/zerolog/log"
)

type Checkov struct{}

func (p *Checkov) Parser(filename string, servicekey string) ([]models.Finding, error) {
	log.Info().Msgf("Parser Checkov")
	findings, err := getFindings(filename)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, err
	}

	for _, finding := range findings {
		log.Info().Msgf(finding.Title)
	}
	return findings, nil
}

func (p *Checkov) GetToolTypes() string {
	return "Checkov"
}

func (p *Checkov) RequiresFile() bool {
	return true
}

func parseJSON(jsonOutput []byte) ([]interface{}, error) {
	var deserialized interface{}

	// Attempt to deserialize JSON
	err := json.Unmarshal(jsonOutput, &deserialized)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Check if deserialized object is a list of JSON objects
	if objList, ok := deserialized.([]interface{}); ok {
		return objList, nil
	}

	// If not a list, return as single-element list
	return []interface{}{deserialized}, nil
}

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
				checkType, _ := treeMap["check_type"].(string)
				findings = append(findings, getItems(treeMap, checkType)...)
			}
		}
	}

	return findings, nil
}

func getItems(tree map[string]interface{}, checkType string) []models.Finding {
	items := []models.Finding{}

	if results, ok := tree["results"].(map[string]interface{}); ok {
		if failedChecks, ok := results["failed_checks"].([]interface{}); ok {
			for _, node := range failedChecks {
				if nodeMap, ok := node.(map[string]interface{}); ok {
					item := getItem(nodeMap, checkType)
					if item != nil {
						items = append(items, *item)
					}
				}
			}
		}
	}

	return items
}

func getItem(vuln map[string]interface{}, checkType string) *models.Finding {
	title := "check_name not found"
	if checkName, ok := vuln["check_name"].(string); ok {
		title = checkName
	}

	description := fmt.Sprintf("Check Type: %s\n", checkType)
	if checkID, ok := vuln["check_id"].(string); ok {
		description += fmt.Sprintf("Check Id: %s\n", checkID)
	}
	if checkName, ok := vuln["check_name"].(string); ok {
		description += fmt.Sprintf("%s\n", checkName)
	}
	log.Info().Msgf("Description: " + description)

	filePath := ""
	if fp, ok := vuln["file_path"].(string); ok {
		filePath = fp
	}

	sourceLine := 0
	if fileLineRange, ok := vuln["file_line_range"].([]interface{}); ok && len(fileLineRange) > 0 {
		if sl, ok := fileLineRange[0].(float64); ok {
			sourceLine = int(sl)
		}
	}

	// resource := ""
	// if res, ok := vuln["resource"].(string); ok {
	// 	resource = res
	// }

	severity := "Medium"
	if sev, ok := vuln["severity"].(string); ok && sev != "" {
		severity = strings.Title(sev)
	}

	mitigation := ""

	references := ""
	if ref, ok := vuln["guideline"].(string); ok {
		references = ref
	}

	return &models.Finding{
		Title:           title,
		RiskDescription: description,
		Severity:        mapSeverity(severity),
		Mitigation:      mitigation,
		Reference:       references,
		FilePath:        filePath,
		Line:            uint64(sourceLine),
		StaticFinding:   true,
		DynamicFinding:  false,
	}
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
