package pipelinerun

import (
	"errors"
	"strconv"
	test_services "vulnerability-management/internal/api/services/test"
	models "vulnerability-management/internal/pkg/models/pipeline-runs"
	"vulnerability-management/internal/pkg/persistence"
	"vulnerability-management/pkg/helpers"

	"github.com/rs/zerolog/log"
)

func DeletePipelineRun(id string) error {
	log.Info().Msgf("DeletePipelineRun initiated for ID: %s", id)

	// Lấy thông tin PipelineRun
	pipelineRun, err := persistence.PipelineRunRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching pipeline run in DeletePipelineRun")
		return errors.New("Pipeline run is not found")
	}

	// Lấy tất cả các Test liên quan đến PipelineRun
	tests, _, err := persistence.TestRepo.Query(map[string]interface{}{"pipeline_run_id": pipelineRun.ID}, 0, 1000)
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching tests for pipeline run ID: %d", pipelineRun.ID)
		return errors.New("Error fetching tests")
	}

	// Xóa tất cả các Test và các thực thể liên quan
	for _, test := range *tests {
		err = test_services.DeleteTest(strconv.FormatUint(test.ID, 10))
		if err != nil {
			log.Error().Err(err).Msgf("Error deleting test ID: %d", test.ID)
			return errors.New("Error deleting test")
		}
	}

	// Xóa PipelineRun
	err = persistence.PipelineRunRepo.Delete(pipelineRun)
	if err != nil {
		log.Error().Err(err).Msgf("Error deleting pipeline run ID: %d", pipelineRun.ID)
		return errors.New("Error deleting pipeline run")
	}

	log.Info().Msgf("Pipeline run deleted successfully for ID: %s", id)
	return nil
}

func GetPipelineRuns(query models.PipelineRun, page string, size string) ([]models.PipelineRun, int, error) {
	log.Info().Msg("GetPipelineRuns function initiated")

	where := map[string]interface{}{}

	if query.BranchName != "" {
		where["branch_name"] = query.BranchName
	}

	if query.CommitHash != "" {
		where["commit_hash"] = query.CommitHash
	}

	if query.Status != 0 {
		where["status"] = query.Status
	}

	if query.RunID != 0 {
		where["run_id"] = query.RunID
	}

	if query.RunURL != "" {
		where["run_url"] = query.RunURL
	}

	offset, limit := helpers.GetPagination(page, size)
	log.Info().
		Interface("where", where).
		Int("offset", offset).
		Int("limit", limit).
		Msg("Query parameters for GetPipelineRuns")

	pipelineRuns, count, err := persistence.PipelineRunRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error querying pipeline runs in GetPipelineRuns")
		return nil, 0, err
	}

	log.Info().Int("count", count).Msg("Pipeline runs fetched successfully in GetPipelineRuns")
	return *pipelineRuns, count, nil
}

func UpdatePipelineRun(body models.PipelineRun) (*models.PipelineRun, error) {

	id := body.ID

	pipelineRun, err := persistence.PipelineRunRepo.Get(strconv.FormatUint(id, 10))
	if err != nil {
		log.Error().Msgf(err.Error())

		return nil, err
	}

	if body.BranchName != "" {
		pipelineRun.BranchName = body.BranchName
	}

	if body.CommitHash != "" {
		pipelineRun.CommitHash = body.CommitHash
	}

	if body.Status != 0 {
		pipelineRun.Status = body.Status
	}

	if body.ProjectID != 0 {
		pipelineRun.ProjectID = body.ProjectID
	}

	if body.RunURL != "" {
		pipelineRun.RunURL = body.RunURL
	}

	if body.RunID != 0 {
		pipelineRun.RunID = body.RunID
	}

	err = persistence.PipelineRunRepo.Update(pipelineRun)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, err
	}

	return pipelineRun, err
}
