package findings

import (
	"errors"
	findingtestservice "vulnerability-management/internal/api/services/finding-test"
	findingtestmodel "vulnerability-management/internal/pkg/models/finding-test"
	models "vulnerability-management/internal/pkg/models/findings"
	"vulnerability-management/internal/pkg/persistence"
	"vulnerability-management/pkg/helpers"

	"github.com/rs/zerolog/log"
)

func SolveFinding(temp_finding models.Finding, testID uint64) error {
	//get Finding in Project
	findings, err := GetFindings(temp_finding, "0", "100")

	if err != nil {
		log.Error().Msgf(err.Error())
		return err
	}
	var finding *models.Finding
	if len(findings) == 0 {
		//create Finding
		finding, err = persistence.FindingRepo.Add(&temp_finding)
		if err != nil {
			log.Error().Msgf(err.Error())
			return err
		}

	} else if len(findings) != 1 {
		log.Error().Msgf(err.Error())
		return errors.New("have many findings")
	} else {
		finding = &findings[0]
		log.Info().Msgf("duplicate")
	}

	//create fiding-test
	findingtestservice.CreateFindingTest(findingtestmodel.FindingTest{
		TestID:    testID,
		FindingID: finding.ID,
	})

	return nil

}

func GetFindings(query models.Finding, page string, size string) ([]models.Finding, error) {

	where := map[string]interface{}{}

	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}

	if query.Title != "" {
		where["title"] = query.Title
	}

	if query.RiskDescription != "" {
		where["risk_description"] = query.RiskDescription
	}

	if query.Severity != 0 {
		where["severity"] = query.Severity
	}

	if query.CWE != 0 {
		where["cwe"] = query.CWE
	}

	if query.Line != 0 {
		where["line"] = query.Line
	}

	if query.FilePath != "" {
		where["file_path"] = query.FilePath
	}

	if query.VulnIDFromTool != "" {
		where["vuln_id_from_tool"] = query.VulnIDFromTool
	}

	if query.UniqueIDFromTool != "" {
		where["unique_id_from_tool"] = query.UniqueIDFromTool
	}

	if query.Mitigation != "" {
		where["mitigation"] = query.Mitigation
	}

	if query.Impact != "" {
		where["impact"] = query.Impact
	}

	if query.Reference != "" {
		where["reference"] = query.Reference
	}

	offset, limit := helpers.GetPagination(page, size)

	findings, _, err := persistence.FindingRepo.Query(where, offset, limit)
	if err != nil {

		return nil, err
	}

	return *findings, nil
}

func CountFindings(query models.Finding) (int, error) {

	where := map[string]interface{}{}

	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}

	if query.Title != "" {
		where["title"] = query.Title
	}

	if query.RiskDescription != "" {
		where["risk_description"] = query.RiskDescription
	}

	if query.Severity != 0 {
		where["severity"] = query.Severity
	}

	if query.CWE != 0 {
		where["cwe"] = query.CWE
	}

	if query.Line != 0 {
		where["line"] = query.Line
	}

	if query.FilePath != "" {
		where["file_path"] = query.FilePath
	}

	if query.VulnIDFromTool != "" {
		where["vuln_id_from_tool"] = query.VulnIDFromTool
	}

	if query.UniqueIDFromTool != "" {
		where["unique_id_from_tool"] = query.UniqueIDFromTool
	}

	if query.Mitigation != "" {
		where["mitigation"] = query.Mitigation
	}

	if query.Impact != "" {
		where["impact"] = query.Impact
	}

	if query.Reference != "" {
		where["reference"] = query.Reference
	}

	if query.Active == false {
		where["active"] = false
	} else if query.Active == true {
		where["active"] = true
	}

	// if c.Query("dynamic_finding") == "false" {
	// 	where["dynamic_finding"] = false
	// } else if c.Query("dynamic_finding") == "true" {
	// 	where["dynamic_finding"] = true
	// }

	// if c.Query("verified") == "false" {
	// 	where["verified"] = false
	// } else if c.Query("verified") == "true" {
	// 	where["verified"] = true
	// }

	// if c.Query("duplicate") == "false" {
	// 	where["duplicate"] = false
	// } else if c.Query("duplicate") == "true" {
	// 	where["duplicate"] = true
	// }

	if query.RiskAccepted  == false {
		where["risk_accepted"] = false
	} else if query.RiskAccepted == true {
		where["risk_accepted"] = true
	}

	// if c.Query("static_finding") == "false" {
	// 	where["static_finding"] = false
	// } else if c.Query("static_finding") == "true" {
	// 	where["static_finding"] = true
	// }

	count, err := persistence.FindingRepo.Count(where)
	if err != nil {
		log.Error().Msgf(err.Error())

		return 0, err
	}

	return count, nil
}
