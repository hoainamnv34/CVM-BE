package tooltypes

import (
	models "vulnerability-management/internal/pkg/models/tool-types"
	"vulnerability-management/internal/pkg/persistence"

	"github.com/rs/zerolog/log"
)

func GetToolType(name string, description string) ([]models.ToolType, error) {
	where := map[string]interface{}{}

	if name != "" {
		where["name"] = name
	}

	if description != "" {
		where["description"] = description
	}
	log.Info().Msgf("%v", where)
	toolTypes, _, err := persistence.ToolTypeRepo.Query(where, 0, 1)

	return *toolTypes, err
}
