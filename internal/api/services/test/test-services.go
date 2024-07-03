package test

import (
	"errors"
	"strconv"
	"vulnerability-management/internal/pkg/persistence"

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

	// Xóa tất cả các FindingTest liên quan
	for _, findingTest := range *findingTests {
		err = persistence.FindingTestRepo.Delete(&findingTest)
		if err != nil {
			log.Error().Err(err).Msgf("Error deleting finding test with ID: %d", findingTest.ID)
			return errors.New("Error deleting finding test")
		}

		// Xóa các Finding liên quan
		findingID := strconv.Itoa(int(findingTest.FindingID))
		finding, err := persistence.FindingRepo.Get(findingID)
		if err != nil {
			log.Error().Err(err).Msgf("Error fetching finding with ID: %d", findingTest.FindingID)
			return errors.New("Error fetching finding")
		}
		err = persistence.FindingRepo.Delete(finding)
		if err != nil {
			log.Error().Err(err).Msgf("Error deleting finding with ID: %d", finding.ID)
			return errors.New("Error deleting finding")
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
