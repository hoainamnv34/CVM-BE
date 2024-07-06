package finding

import (
	"errors"
	"fmt"
	"strconv"
	finding_test_service "vulnerability-management/internal/api/services/finding-test"
	test_service "vulnerability-management/internal/api/services/test"
	finding_test_model "vulnerability-management/internal/pkg/models/finding-test"
	models "vulnerability-management/internal/pkg/models/findings"
	persistence "vulnerability-management/internal/pkg/persistence"
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

func SolveDuplicateFinding(newFindings []models.Finding, testID uint64, projectID uint64) error {
	log.Info().Msg("SolveDuplicateFinding initiated")

	// Lấy tất cả các finding cũ trong project
	offset, limit := helpers.GetPagination("0", "1000")
	oldFindings, _, err := persistence.FindingRepo.QueryByProjectID(projectID, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error getting findings in SolveDuplicateFinding")
		return err
	}


	// Tạo một map các findings cũ để kiểm tra sự tồn tại
	oldFindingMap := make(map[string]models.Finding)
	for _, oldFinding := range *oldFindings {
		key := generateFindingKey(oldFinding)
		oldFindingMap[key] = oldFinding
	}

	// Xử lý các finding mới
	for _, newFinding := range newFindings {
		newFinding.ProjectID = projectID

		key := generateFindingKey(newFinding)
		var findingID uint64

		// Nếu tồn tại thì cập nhật trường Duplicate và Active
		if oldFinding, exists := oldFindingMap[key]; exists {
			log.Info().Msgf("Duplicate finding found for key: %s", key)
			findingID = oldFinding.ID
			oldFinding.Duplicate = true
			if !oldFinding.Active {
				oldFinding.Active = true
			}

			_, err = UpdateFinding(strconv.FormatUint(oldFinding.ID, 10), oldFinding)
			if err != nil {
				log.Error().Err(err).Msg("Error updating finding as Duplicate in SolveDuplicateFinding")
				return err
			}
		} else {
			// Nếu chưa tồn tại thì tạo mới
			log.Info().Msg("Creating new finding in SolveDuplicateFinding")
			fd, err := persistence.FindingRepo.Add(&newFinding)
			if err != nil {
				log.Error().Err(err).Msg("Error adding finding in SolveDuplicateFinding")
				return err
			}
			findingID = fd.ID
		}

		// Tạo finding-test
		_, err = finding_test_service.CreateFindingTest(finding_test_model.FindingTest{
			TestID:    testID,
			FindingID: findingID,
		})
		if err != nil {
			log.Error().Err(err).Msg("Error creating finding-test in SolveDuplicateFinding")
			return err
		}
	}

	log.Info().Msg("Findings processed successfully in SolveDuplicateFinding")
	return nil
}


// CloseObsoleteFindings closes findings that are no longer in the new list
func CloseObsoleteFindings(projectID uint64, testName string, newFindings []models.Finding) error {
	log.Info().Msgf("CloseObsoleteFindings initiated for Test Name: %s", testName)

	// Lấy tất cả các test cùng tên và cùng project
	oldTests, testsCount, err := test_service.GetTestByProjectIDAndName(projectID, testName, "0", "0")
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching tests with name: %v in projectID: %v", testName, projectID)
		return errors.New("Error fetching tests")
	}

	if testsCount == 0 {
		return fmt.Errorf("No test with name %v in project %v", testName, projectID)
	}

	if testsCount == 1 {
		log.Info().Msgf("No old test with name %v in project %v", testName, projectID)
		return nil
	}

	// Lấy test mới nhất
	latestTest := oldTests[1]

	// Lấy tất cả các Finding liên quan
	offset, limit := helpers.GetPagination("0", "0")
	findings, _, err := persistence.FindingRepo.QueryByTestID(latestTest.ID, offset, limit)

	if err != nil {
		log.Error().Err(err).Msgf("Error fetching findings for test ID: %d", latestTest.ID)
		return errors.New("Error fetching findings")
	}

	// Tạo một map các findings mới để kiểm tra sự tồn tại
	newFindingMap := make(map[string]struct{})
	for _, newFinding := range newFindings {
		newFinding.ProjectID = projectID
		key := generateFindingKey(newFinding)
		fmt.Print("new: %v", key)
		newFindingMap[key] = struct{}{}
	}

	// Đóng các findings cũ không tồn tại trong danh sách mới
	for _, finding := range *findings {
		
		key := generateFindingKey(finding)
		fmt.Print("old: %v", key)
		
		if _, exists := newFindingMap[key]; !exists {
			if finding.Active {
				finding.Active = false
				err = persistence.FindingRepo.Update(&finding)
				if err != nil {
					log.Error().Err(err).Msgf("Error closing finding with ID: %d", finding.ID)
					return errors.New("Error closing finding")
				}
				log.Info().Msgf("Finding closed successfully for ID: %d", finding.ID)
			}
		}
	}

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

func UpdateFinding(id string, updatedFinding models.Finding) (*models.Finding, error) {
	log.Info().Msgf("UpdateFinding initiated for ID: %s", id)

	// Lấy thông tin Finding hiện tại
	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching finding in UpdateFinding")
		return nil, errors.New("Finding is not found")
	}

	// Cập nhật các thuộc tính của Finding
	if updatedFinding.ProjectID != 0 {
		finding.ProjectID = updatedFinding.ProjectID
	}
	if updatedFinding.Title != "" {
		finding.Title = updatedFinding.Title
	}
	if updatedFinding.Description != "" {
		finding.Description = updatedFinding.Description
	}
	if updatedFinding.Severity != 0 {
		finding.Severity = updatedFinding.Severity
	}
	if updatedFinding.CWE != 0 {
		finding.CWE = updatedFinding.CWE
	}
	if updatedFinding.Line != 0 {
		finding.Line = updatedFinding.Line
	}
	if updatedFinding.FilePath != "" {
		finding.FilePath = updatedFinding.FilePath
	}
	if updatedFinding.VulnIDFromTool != "" {
		finding.VulnIDFromTool = updatedFinding.VulnIDFromTool
	}
	if updatedFinding.Mitigation != "" {
		finding.Mitigation = updatedFinding.Mitigation
	}
	if updatedFinding.Reference != "" {
		finding.Reference = updatedFinding.Reference
	}
	if updatedFinding.Active != finding.Active {
		finding.Active = updatedFinding.Active
	}
	if updatedFinding.DynamicFinding != finding.DynamicFinding {
		finding.DynamicFinding = updatedFinding.DynamicFinding
	}
	if updatedFinding.Duplicate != finding.Duplicate {
		finding.Duplicate = updatedFinding.Duplicate
	}
	if updatedFinding.RiskAccepted != finding.RiskAccepted {
		finding.RiskAccepted = updatedFinding.RiskAccepted
	}
	if updatedFinding.StaticFinding != finding.StaticFinding {
		finding.StaticFinding = updatedFinding.StaticFinding
	}

	// Cập nhật Finding trong cơ sở dữ liệu
	err = persistence.FindingRepo.Update(finding)
	if err != nil {
		log.Error().Err(err).Msg("Error updating finding in UpdateFinding")
		return nil, errors.New("Error updating finding")
	}

	log.Info().Msgf("Finding updated successfully for ID: %s", id)
	return finding, nil
}



// generateFindingKey generates a unique key for a finding based on important fields
func generateFindingKey(finding models.Finding) string {
	return fmt.Sprintf("%d-%s-%d-%d-%s-%d", finding.ProjectID, finding.Title, finding.Severity, finding.Line, finding.FilePath, finding.CWE)
}