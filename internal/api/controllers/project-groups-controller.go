package controllers

import (
	"net/http"

	project_group_services "vulnerability-management/internal/api/services/project-group"
	models "vulnerability-management/internal/pkg/models/project-groups"
	persistence "vulnerability-management/internal/pkg/persistence"
	helpers "vulnerability-management/pkg/helpers"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetProjectGroupByID godoc
// @Summary     Get project group by ID
// @Description Get project group by ID
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/project-groups/{id} [get]
// @Tags        ProjectGroup
func GetProjectGroupByID(c *gin.Context) {
	id := c.Param("id")
	log.Info().Str("id", id).Msg("GetProjectGroupByID initiated")

	projectGroup, err := persistence.ProjectGroupRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching project group in GetProjectGroupByID")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project group is not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Project group fetched successfully in GetProjectGroupByID")

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    projectGroup,
	})
}

// GetProjectGroups godoc
// @Summary     Get project group by query
// @Description Get project group by query
// @Produce     json
// @Param       name        query    string  false "name"
// @Param       description query    string  false "description"
// @Param       member      query    integer false "member"
// @Param       page        query    integer false "page"
// @Param       size        query    integer false "size"
// @Success     200         {object} http_res.HTTPResponse
// @Router      /api/project-groups [get]
// @Tags        ProjectGroup
func GetProjectGroups(c *gin.Context) {
	log.Info().Msg("GetProjectGroups initiated")

	query := models.ProjectGroup{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in GetProjectGroups")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	where := map[string]interface{}{}
	if query.Name != "" {
		where["name"] = query.Name
	}
	if query.Description != "" {
		where["description"] = query.Description
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))
	log.Info().
		Interface("where", where).
		Int("offset", offset).
		Int("limit", limit).
		Msg("Query parameters for GetProjectGroups")

	projectGroups, count, err := persistence.ProjectGroupRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error querying project groups in GetProjectGroups")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project groups not found",
		})
		return
	}

	log.Info().
		Int("count", count).
		Msg("Project groups fetched successfully in GetProjectGroups")

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      projectGroups,
		DataCount: count,
	})
}

// ProjectGroupRequest represents the payload for creating a project group.
type ProjectGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CreateProjectGroup godoc
// @Summary     Create project group
// @Description Create project group
// @Accept      json
// @Produce     json
// @Param       body body     ProjectGroupRequest true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/project-groups [post]
// @Tags        ProjectGroup
func CreateProjectGroup(c *gin.Context) {
	log.Info().Msg("CreateProjectGroup initiated")

	var body ProjectGroupRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in CreateProjectGroup")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	projectGroup := models.ProjectGroup{
		Name:        body.Name,
		Description: body.Description,
	}

	res, err := persistence.ProjectGroupRepo.Add(&projectGroup)
	if err != nil {
		log.Error().Err(err).Msg("Error adding project group in CreateProjectGroup")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})
		return
	}

	log.Info().Msg("Project group created successfully in CreateProjectGroup")
	c.JSON(http.StatusCreated, http_res.HTTPResponse{
		Code:    http.StatusCreated,
		Message: "Success",
		Data:    res,
	})

}

// UpdateProjectGroup godoc
// @Summary     Update project group by ID
// @Description Update project group by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer             true "id" min(1)
// @Param       body body     ProjectGroupRequest true "Body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/project-groups/{id} [put]
// @Tags        ProjectGroup
func UpdateProjectGroup(c *gin.Context) {
	log.Info().Msg("UpdateProjectGroup initiated")

	var body ProjectGroupRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in UpdateProjectGroup")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	id := c.Param("id")
	projectGroup, err := persistence.ProjectGroupRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching project group in UpdateProjectGroup")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project group is not found",
		})
		return
	}

	if body.Name != "" {
		projectGroup.Name = body.Name
	}
	if body.Description != "" {
		projectGroup.Description = body.Description
	}

	err = persistence.ProjectGroupRepo.Update(projectGroup)
	if err != nil {
		log.Error().Err(err).Msg("Error updating project group in UpdateProjectGroup")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project group is not found",
		})
		return
	}

	log.Info().Msg("Project group updated successfully in UpdateProjectGroup")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// DeleteProjectGroup godoc
// @Summary     Delete project group by ID
// @Description Delete project group by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/project-groups/{id} [delete]
// @Tags        ProjectGroup
func DeleteProjectGroup(c *gin.Context) {
	log.Info().Msg("DeleteProjectGroup initiated")

	id := c.Param("id")

	err := project_group_services.DeleteProjectGroup(id)
	if err != nil {
		log.Error().Err(err).Msg("Error deleting project group in DeleteProjectGroup")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: err.Error(),
		})
		return
	}

	log.Info().Msg("Project group deleted successfully in DeleteProjectGroup")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
