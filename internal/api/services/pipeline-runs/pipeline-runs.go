package pipelineruns

import (
	models "vulnerability-management/internal/pkg/models/pipeline-runs"
	"vulnerability-management/internal/pkg/persistence"
	"vulnerability-management/pkg/helpers"

	"github.com/rs/zerolog/log"
)

func GetPipelineRuns(query models.PipelineRun, page string, size string) ([]models.PipelineRun, error) {
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

	if query.PipelineRunID != 0 {
		where["pipeline_run_id"] = query.PipelineRunID
	}

	if query.PipelineRunURL != "" {
		where["pipeline_run_url"] = query.PipelineRunURL
	}

	offset, limit := helpers.GetPagination(page, size)

	pipelineRuns, _, err := persistence.PipelineRunRepo.Query(where, offset, limit)
	if err != nil {

		return nil, err
	}

	return *pipelineRuns, nil
}

func UpdatePipelineRun(body models.PipelineRun) (*models.PipelineRun, error) {

	id := body.ID

	pipelineRun, err := persistence.PipelineRunRepo.Get(string(id))
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

	if body.PipelineRunURL != "" {
		pipelineRun.PipelineRunURL = body.PipelineRunURL
	}

	if body.PipelineRunID != 0 {
		pipelineRun.PipelineRunID = body.PipelineRunID
	}

	err = persistence.PipelineRunRepo.Update(pipelineRun)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, err
	}

	return pipelineRun, err
}
