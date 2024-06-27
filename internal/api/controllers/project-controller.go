package controllers

import (
	"net/http"

	models "vulnerability-management/internal/pkg/models/projects"
	persistence "vulnerability-management/internal/pkg/persistence"
	helpers "vulnerability-management/pkg/helpers"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetProjectByID godoc
// @Summary     Get project by ID
// @Description Get project by ID
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/projects/{id} [get]
// @Security    Authorization Token
// @Tags        Project
func GetProjectByID(c *gin.Context) {
	id := c.Param("id")

	project, err := persistence.ProjectRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    project,
	})
}

// GetProjects godoc
// @Summary     Get projects by query
// @Description Get projects by query
// @Produce     json
// @Param       name             query    string  false "name"
// @Param       description      query    string  false "description"
// @Param       member           query    integer false "member"
// @Param       project_group_id query    integer false "project_group_id"
// @Param       repository_url   query    string  false "repository_url"
// @Param       page             query    integer false "page"
// @Param       size             query    integer false "size"
// @Success     200              {object} http_res.HTTPResponse
// @Router      /api/projects [get]
// @Security    Authorization Token
// @Tags        Project
func GetProjects(c *gin.Context) {
	query := models.Project{}

	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Msgf(err.Error())

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

	if query.ProjectGroupID != 0 {
		where["project_group_id"] = query.ProjectGroupID
	}

	if query.RepositoryURL != "" {
		where["repository_url"] = query.RepositoryURL
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	projects, count, err := persistence.ProjectRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Projects not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      projects,
		DataCount: count,
	})
}

// CreateProject godoc
// @Summary     Create project
// @Description Create project
// @Accept      json
// @Produce     json
// @Param       body body     models.Project true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/projects [post]
// @Tags        Project
func CreateProject(c *gin.Context) {
	body := models.Project{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})

		return
	}

	project := models.Project{
		Name:                 body.Name,
		Description:          body.Description,
		ProjectGroupID:       body.ProjectGroupID,
		RepositoryURL:        body.RepositoryURL,
		PipelineEvaluationID: body.PipelineEvaluationID,
	}

	res, err := persistence.ProjectRepo.Add(&project)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})

		return
	}

	c.JSON(http.StatusCreated, http_res.HTTPResponse{
		Code:    http.StatusCreated,
		Message: "Success",
		Data:    res,
	})
}

// UpdateProject godoc
// @Summary     Update project by ID
// @Description Update project by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer        true "id" min(1)
// @Param       body body     models.Project true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/projects/{id} [put]
// @Tags        Project
func UpdateProject(c *gin.Context) {
	body := models.Project{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})

		return
	}

	id := c.Param("id")

	project, err := persistence.ProjectRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project is not found",
		})

		return
	}

	if body.Name != "" {
		project.Name = body.Name
	}

	if body.Description != "" {
		project.Description = body.Description
	}

	if body.ProjectGroupID != 0 {
		project.ProjectGroupID = body.ProjectGroupID
	}

	if body.RepositoryURL != "" {
		project.RepositoryURL = body.RepositoryURL
	}
	
	if body.PipelineEvaluationID != 0 {
		project.PipelineEvaluationID = body.PipelineEvaluationID
	}

	err = persistence.ProjectRepo.Update(project)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// DeleteProject godoc
// @Summary     Delete project by ID
// @Description Delete project by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/projects/{id} [delete]
// @Tags        Project
func DeleteProject(c *gin.Context) {
	id := c.Param("id")

	project, err := persistence.ProjectRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project is not found",
		})

		return
	}

	err = persistence.ProjectRepo.Delete(project)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
