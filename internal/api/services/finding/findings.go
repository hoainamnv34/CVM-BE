package finding

import (
	"errors"
	finding_test_service "vulnerability-management/internal/api/services/finding-test"
	finding_test_model "vulnerability-management/internal/pkg/models/finding-test"
	models "vulnerability-management/internal/pkg/models/findings"
	"vulnerability-management/internal/pkg/persistence"
	"vulnerability-management/pkg/helpers"

	"github.com/rs/zerolog/log"
)


func DeleteFinding(id string) error {
	log.Info().Msgf("DeleteFinding initiated for ID: %s", id)

	// Lấy thông tin Finding
	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching finding in DeleteFinding")
		return errors.New("Finding is not found")
	}

	// Xóa các FindingTest liên quan
	findingTests, _, err := persistence.FindingTestRepo.Query(map[string]interface{}{"finding_id": finding.ID}, 0, 1000)
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching finding tests for finding with ID: %d in DeleteFinding", finding.ID)
		return errors.New("Error fetching finding tests for finding")
	}

	for _, findingTest := range *findingTests {
		err = persistence.FindingTestRepo.Delete(&findingTest)
		if err != nil {
			log.Error().Err(err).Msgf("Error deleting finding test with ID: %d in DeleteFinding", findingTest.ID)
			return errors.New("Error deleting finding test")
		}
	}

	// Xóa Finding
	err = persistence.FindingRepo.Delete(finding)
	if err != nil {
		log.Error().Err(err).Msg("Error deleting finding in DeleteFinding")
		return errors.New("Error deleting finding")
	}

	log.Info().Msgf("Finding deleted successfully for ID: %s", id)
	return nil
}


func SolveFinding(temp_finding models.Finding, testID uint64) error {
	log.Info().Msg("SolveFinding initiated")

	// Get findings in project
	findings, err := GetFindings(temp_finding, "0", "100")
	if err != nil {
		log.Error().Err(err).Msg("Error getting findings in SolveFinding")
		return err
	}

	var finding *models.Finding
	if len(findings) == 0 {
		// Create finding
		finding, err = persistence.FindingRepo.Add(&temp_finding)
		if err != nil {
			log.Error().Err(err).Msg("Error adding finding in SolveFinding")
			return err
		}
	} else if len(findings) != 1 {
		log.Error().Msg("Multiple findings found in SolveFinding")
		return errors.New("multiple findings found")
	} else {
		finding = &findings[0]
		log.Info().Msg("Duplicate finding found in SolveFinding")
	}

	// Create finding-test
	_, err = finding_test_service.CreateFindingTest(finding_test_model.FindingTest{
		TestID:    testID,
		FindingID: finding.ID,
	})
	if err != nil {
		log.Error().Err(err).Msg("Error creating finding-test in SolveFinding")
		return err
	}

	log.Info().Msg("Finding solved successfully in SolveFinding")
	return nil
}

func GetFindings(query models.Finding, page string, size string) ([]models.Finding, error) {
	log.Info().Msg("GetFindings initiated")

	where := map[string]interface{}{}
	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}
	if query.Title != "" {
		where["title"] = query.Title
	}
	if query.Description != "" {
		where["risk_description"] = query.Description
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
	if query.Mitigation != "" {
		where["mitigation"] = query.Mitigation
	}
	if query.Reference != "" {
		where["reference"] = query.Reference
	}

	offset, limit := helpers.GetPagination(page, size)
	log.Info().
		Interface("where", where).
		Int("offset", offset).
		Int("limit", limit).
		Msg("Query parameters for GetFindings")

	findings, _, err := persistence.FindingRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error querying findings in GetFindings")
		return nil, err
	}

	log.Info().Msg("Findings fetched successfully in GetFindings")
	return *findings, nil
}

func CountFindings(query models.Finding) (int, error) {
	log.Info().Msg("CountFindings initiated")

	where := map[string]interface{}{}
	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}
	if query.Title != "" {
		where["title"] = query.Title
	}
	if query.Description != "" {
		where["description"] = query.Description
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
	if query.Mitigation != "" {
		where["mitigation"] = query.Mitigation
	}
	if query.Reference != "" {
		where["reference"] = query.Reference
	}
	if query.Active {
		where["active"] = true
	} else {
		where["active"] = false
	}
	if query.RiskAccepted {
		where["risk_accepted"] = true
	} else {
		where["risk_accepted"] = false
	}

	log.Info().Interface("where", where).Msg("Query parameters for CountFindings")

	count, err := persistence.FindingRepo.Count(where)
	if err != nil {
		log.Error().Err(err).Msg("Error counting findings in CountFindings")
		return 0, err
	}

	log.Info().Int("count", count).Msg("Findings counted successfully in CountFindings")
	return count, nil
}


