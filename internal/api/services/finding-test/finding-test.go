package findingtest

import (
	models "vulnerability-management/internal/pkg/models/finding-test"
	"vulnerability-management/internal/pkg/persistence"
)

func CreateFindingTest(findingTest models.FindingTest) (*models.FindingTest, error) {
	res, err := persistence.FindingTestRepo.Add(&findingTest)
	if err != nil {
		return nil, err
	}

	return res, nil
}
