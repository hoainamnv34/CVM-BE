package gitleaks

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	models "vulnerability-management/internal/pkg/models/findings"
	tool_models "vulnerability-management/internal/pkg/models/tool-types"

	"github.com/rs/zerolog/log"
)

type GitLeaks struct{}

func (p *GitLeaks) Parser(toolInfo tool_models.ToolInfo) ([]models.Finding, error) {
	log.Info().Msgf("Parser GitLeaks")
	findings, err := getFindings(toolInfo.ReportFile)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, err
	}

	// for _, finding := range findings {
	// 	log.Info().Msgf(finding.Title)
	// }
	return findings, nil
}

func getFindings(filename string) ([]models.Finding, error) {
	file, err := os.Open(filename)
	if err != nil {
		log.Error().Msgf("open file error")
		return nil, err
	}
	defer file.Close()

	var issues []map[string]interface{}
	err = json.NewDecoder(file).Decode(&issues)
	if err != nil {
		return nil, err
	}
	if issues == nil {
		return []models.Finding{}, nil
	}

	dupes := make(map[string]models.Finding)

	for _, issue := range issues {
		if _, ok := issue["Description"]; ok {
			err := getFinding(issue, dupes)

			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("getFindings: %s", "Format is not recognized for Gitleaks")
		}
	}

	var findings []models.Finding
	for _, finding := range dupes {
		findings = append(findings, finding)
	}

	return findings, nil
}

func getFinding(issue map[string]interface{}, dupes map[string]models.Finding) error {
	reason := issue["Description"].(string)
	var line uint64
	if v, ok := issue["StartLine"].(float64); ok {
		line = uint64(v)
	} else {
		line = 0
	}
	match := issue["Match"].(string)
	secret := issue["Secret"].(string)
	filePath := issue["File"].(string)
	// commit := issue["Commit"].(string)
	// date := issue["Date"].(string)
	// message := issue["Message"].(string)
	ruleID := issue["RuleID"].(string)

	title := fmt.Sprintf("Hard coded %s found in %s", reason, filePath)

	description := ""
	if secret != "" {
		description += fmt.Sprintf("**Secret:** %s\n", secret)
	}
	if match != "" {
		description += fmt.Sprintf("**Match:** %s\n", match)
	}
	// if message != "" {
	// 	if len(message) > 1 {
	// 		description += fmt.Sprintf("**Commit message:**\n```\n%s\n```\n", message)
	// 	} else {
	// 		description += fmt.Sprintf("**Commit message:** %s\n", message)
	// 	}
	// }
	// if commit != "" {
	// 	description += fmt.Sprintf("**Commit hash:** %s\n", commit)
	// }
	// if date != "" {
	// 	description += fmt.Sprintf("**Commit date:** %s\n", date)
	// }
	if ruleID != "" {
		description += fmt.Sprintf("**Rule Id:** %s", ruleID)
	}
	if description[len(description)-1] == '\n' {
		description = description[:len(description)-1]
	}

	var severity uint64 = 3

	dupeKey := md5.New()
	dupeKey.Write([]byte(title + secret + fmt.Sprint(line)))
	hash := hex.EncodeToString(dupeKey.Sum(nil))

	if existingFinding, ok := dupes[hash]; ok {
		existingFinding.Description += "\n\n***\n\n" + description
		dupes[hash] = existingFinding
	} else {
		dupes[hash] = models.Finding{
			Title:          title,
			CWE:            798,
			Description:    description,
			Severity:       severity,
			FilePath:       filePath,
			Line:           line,
			Reference:      "",
			Active:         true,
			DynamicFinding: false,
			StaticFinding:  true,
		}
	}

	return nil
}

func (p *GitLeaks) GetToolTypes() string {
	return "Gitleaks"
}

func (p *GitLeaks) RequiresFile() bool {
	return true
}
