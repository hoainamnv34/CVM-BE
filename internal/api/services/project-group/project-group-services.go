package projectgroup

import (
	"errors"
	"strconv"
	project_services "vulnerability-management/internal/api/services/project"
	persistence "vulnerability-management/internal/pkg/persistence"

	"github.com/rs/zerolog/log"
)

func DeleteProjectGroup(id string) error {
	log.Info().Msgf("DeleteProjectGroup initiated for ID: %s", id)

	// Lấy thông tin ProjectGroup
	projectGroup, err := persistence.ProjectGroupRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching project group in DeleteProjectGroup")
		return errors.New("Project group is not found")
	}

	// Lấy tất cả các Project liên quan đến ProjectGroup
	projects, _, err := persistence.ProjectRepo.Query(map[string]interface{}{"project_group_id": projectGroup.ID}, 0, 1000)
	if err != nil {
		log.Error().Err(err).Msgf("Error fetching projects for project group ID: %d", projectGroup.ID)
		return errors.New("Error fetching projects")
	}

	// Xóa tất cả các Project và các thực thể liên quan
	for _, project := range *projects {
		err = project_services.DeleteProject(strconv.FormatUint(project.ID, 10))
		if err != nil {
			log.Error().Err(err).Msgf("Error deleting project ID: %d", project.ID)
			return errors.New("Error deleting project")
		}
	}

	// Xóa ProjectGroup
	err = persistence.ProjectGroupRepo.Delete(projectGroup)
	if err != nil {
		log.Error().Err(err).Msgf("Error deleting project group ID: %d", projectGroup.ID)
		return errors.New("Error deleting project group")
	}

	log.Info().Msgf("Project group deleted successfully for ID: %s", id)
	return nil
}
