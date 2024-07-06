package test

import (
	"errors"
	"strconv"
	models "vulnerability-management/internal/pkg/models/tests"
	"vulnerability-management/internal/pkg/persistence"
	"vulnerability-management/pkg/helpers"

	"github.com/rs/zerolog/log"
)

func DeleteTest(id string) error {
	log.Info().Msgf("DeleteTest initiated for ID: %s", id)

	// Lấy thông tin Test
	test, err := persistence.TestRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching test in DeleteTest")
		return errors.New("Test is not found")
	}

	// Lấy tất cả các FindingTest liên quan
	findingTests, _, err := persistence.FindingTestRepo.Query(map[string]interface{}{"test_id": test.ID}, 0, 1000)
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching finding tests")
		return errors.New("Error fetching finding tests")
	}

	for _, findingTest := range *findingTests {
		// Xóa tất cả các FindingTest liên quan
		err = persistence.FindingTestRepo.Delete(&findingTest)
		if err != nil {
			log.Error().Err(err).Msgf("Error deleting finding test with ID: %d", findingTest.ID)
			return errors.New("Error deleting finding test")
		}

		// Xóa Finding liên quan
		findingID := strconv.Itoa(int(findingTest.FindingID))
		finding, err := persistence.FindingRepo.Get(findingID)
		if err != nil {
			log.Error().Err(err).Msgf("Error fetching finding with ID: %d", findingTest.FindingID)
			return errors.New("Error fetching finding")
		}

		// Kiểm tra xem Finding này có thuộc nhiều Tests không
		if finding.Duplicate {
			// Lấy tất cả các FindingTests liên quan đến Finding này
			findingTestsByFinding, _, err := persistence.FindingTestRepo.Query(map[string]interface{}{"finding_id": finding.ID}, 0, 1000)
			if err != nil {
				log.Error().Err(err).Msgf("Error fetching finding tests by finding ID: %d", finding.ID)
				return errors.New("Error fetching finding tests by finding")
			}

			// Nếu số lượng FindingTests liên quan bằng 1 thì đặt Duplicate là false
			if len(*findingTestsByFinding) == 1 {
				finding.Duplicate = false
				err = persistence.FindingRepo.Update(finding)
				if err != nil {
					log.Error().Err(err).Msgf("Error updating finding with ID: %d", finding.ID)
					return errors.New("Error updating finding")
				}
			}
		} else {
			err = persistence.FindingRepo.Delete(finding)
			if err != nil {
				log.Error().Err(err).Msgf("Error deleting finding with ID: %d", finding.ID)
				return errors.New("Error deleting finding")
			}
		}

	}

	// Xóa Test
	err = persistence.TestRepo.Delete(test)
	if err != nil {
		log.Error().Err(err).Msg("Error deleting test in DeleteTest")
		return errors.New("Error deleting test")
	}

	log.Info().Msgf("Test deleted successfully for ID: %s", id)
	return nil
}


func GetTests(query models.Test, page string, size string) ([]models.Test, int, error) {
	log.Info().Msg("GetTests Service initiated")

	where := map[string]interface{}{}
	if query.Name != "" {
		where["name"] = query.Name
	}
	if query.PipelineRunID != 0 {
		where["pipeline_run_id"] = query.PipelineRunID
	}
	if query.ToolTypeID != 0 {
		where["tool_type_id"] = query.ToolTypeID
	}

	offset, limit := helpers.GetPagination(page, size)
	log.Info().
		Interface("where", where).
		Int("offset", offset).
		Int("limit", limit).
		Msg("Query parameters for GetTests")

	tests, count, err := persistence.TestRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error querying tests in GetTests")
		return nil, 0,  errors.New("Tests not found")
	}

	log.Info().Int("count", count).Msg("Tests fetched successfully in GetTests")
	return *tests,count, nil
}

func GetTestByProjectIDAndName(projectID uint64, testName string, page string, size string) ([]models.Test, int, error) {
	log.Info().Msgf("GetTestByProjectIDAndName initiated for ProjectID: %d, TestName: %s", projectID, testName)
	offset, limit := helpers.GetPagination(page, size)
	tests, count, err := persistence.TestRepo.QueryByProjectIDAndName(projectID, testName, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching tests in GetTestByProjectIDAndName")
		return nil, 0, errors.New("Error fetching tests")
	}

	return *tests, count, nil
}