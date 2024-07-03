package project

import (
	"errors"
	"strconv"
	pipelinerun_services "vulnerability-management/internal/api/services/pipeline-run"
	"vulnerability-management/internal/pkg/persistence"

	"github.com/rs/zerolog/log"
)

func DeleteProject(id string) error {
	log.Info().Msgf("DeleteProject initiated for ID: %s", id)

	// Lấy thông tin Project
	project, err := persistence.ProjectRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching project in DeleteProject")
		return errors.New("Project is not found")
	}

	// Lấy tất cả các PipelineRun liên quan đến Project
	pipelineRuns, _, err := persistence.PipelineRunRepo.Query(map[string]interface{}{"project_id": project.ID}, 0, 1000)
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching pipeline runs for project ID: %d", project.ID)
		return errors.New("Error fetching pipeline runs")
	}

	// Xóa tất cả các PipelineRun và các thực thể liên quan
	for _, pipelineRun := range *pipelineRuns {
		err = pipelinerun_services.DeletePipelineRun(strconv.FormatUint(pipelineRun.ID, 10))
		if err != nil {
			log.Error().Err(err).Msgf("Error deleting pipeline run ID: %d", pipelineRun.ID)
			return errors.New("Error deleting pipeline run")
		}
	}

	// Lấy tất cả các Finding liên quan đến Project
	findings, _, err := persistence.FindingRepo.Query(map[string]interface{}{"project_id": project.ID}, 0, 1000)
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching findings for project ID: %d", project.ID)
		return errors.New("Error fetching findings")
	}

	// Xóa tất cả các Finding liên quan
	for _, finding := range *findings {
		err = persistence.FindingRepo.Delete(&finding)
		if err != nil {
			log.Error().Err(err).Msgf("Error deleting finding ID: %d", finding.ID)
			return errors.New("Error deleting finding")
		}
	}

	// Xóa Project
	err = persistence.ProjectRepo.Delete(project)
	if err != nil {
		log.Error().Err(err).Msgf("Error deleting project ID: %d", project.ID)
		return errors.New("Error deleting project")
	}

	log.Info().Msgf("Project deleted successfully for ID: %s", id)
	return nil
}
