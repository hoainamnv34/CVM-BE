package evaluatepipeline

import (
	pipelineruns "vulnerability-management/internal/api/services/pipeline-runs"
	models "vulnerability-management/internal/pkg/models/pipeline-runs"
)

func SolvePipelineRunStatus(pipelineRun models.PipelineRun, evaluate bool) error {
	// fail or success
	if evaluate {
		pipelineRun.Status = 2
	} else {
		pipelineRun.Status = 3
	}

	//update
	_, err := pipelineruns.UpdatePipelineRun(pipelineRun)
	if err != nil {
		return err
	}

	//close finding
	//get all findings in pipelineRun
	//
	return nil
}
