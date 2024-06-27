package controllers

import (
	"net/http"

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
// @Security    Authorization Token
// @Tags        ProjectGroup
func GetProjectGroupByID(c *gin.Context) {
	id := c.Param("id")

	projectGroup, err := persistence.ProjectGroupRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project group is not found",
		})

		return
	}

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
// @Security    Authorization Token
// @Tags        ProjectGroup
func GetProjectGroups(c *gin.Context) {
	query := models.ProjectGroup{}

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

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	projectGroups, count, err := persistence.ProjectGroupRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project groups not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      projectGroups,
		DataCount: count,
	})
}

// CreateProjectGroup godoc
// @Summary     Create project group
// @Description Create project group
// @Accept      json
// @Produce     json
// @Param       body body     models.ProjectGroup true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/project-groups [post]
// @Tags        ProjectGroup
func CreateProjectGroup(c *gin.Context) {

	body := models.ProjectGroup{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

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

// UpdateProjectGroup godoc
// @Summary     Update project group by ID
// @Description Update project group by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer             true "id" min(1)
// @Param       body body     models.ProjectGroup true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/project-groups/{id} [put]
// @Tags        ProjectGroup
func UpdateProjectGroup(c *gin.Context) {
	body := models.ProjectGroup{}
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

	projectGroup, err := persistence.ProjectGroupRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

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
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project group is not found",
		})

		return
	}

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
	id := c.Param("id")

	projectGroup, err := persistence.ProjectGroupRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project group is not found",
		})

		return
	}

	err = persistence.ProjectGroupRepo.Delete(projectGroup)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project group is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
