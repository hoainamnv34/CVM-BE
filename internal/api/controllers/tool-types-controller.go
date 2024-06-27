package controllers

import (
	"net/http"

	models "vulnerability-management/internal/pkg/models/tool-types"
	persistence "vulnerability-management/internal/pkg/persistence"
	helpers "vulnerability-management/pkg/helpers"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetToolTypeByID godoc
// @Summary     Get tool type by ID
// @Description Get tool type by ID
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/tool-types/{id} [get]
// @Security    Authorization Token
// @Tags        ToolType
func GetToolTypeByID(c *gin.Context) {
	id := c.Param("id")

	toolType, err := persistence.ToolTypeRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    toolType,
	})
}

// GetToolTypes godoc
// @Summary     Get tool types by query
// @Description Get tool types by query
// @Produce     json
// @Param       name        query    string  false "name"
// @Param       description query    string  false "description"
// @Param       url         query    string  false "url"
// @Param       api_key     query    string  false "api_key"
// @Param       page        query    integer false "page"
// @Param       size        query    integer false "size"
// @Success     200         {object} http_res.HTTPResponse
// @Router      /api/tool-types [get]
// @Security    Authorization Token
// @Tags        ToolType
func GetToolTypes(c *gin.Context) {
	query := models.ToolType{}

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

	if query.Url != "" {
		where["url"] = query.Url
	}

	if query.ApiKey != "" {
		where["api_key"] = query.ApiKey
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	toolTypes, count, err := persistence.ToolTypeRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool types not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      toolTypes,
		DataCount: count,
	})
}

// CreateToolType godoc
// @Summary     Create tool type
// @Description Create tool type
// @Accept      json
// @Produce     json
// @Param       body body     models.ToolType true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/tool-types [post]
// @Tags        ToolType
func CreateToolType(c *gin.Context) {
	body := models.ToolType{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})

		return
	}

	toolType := models.ToolType{
		Name:        body.Name,
		Description: body.Description,
	}

	res, err := persistence.ToolTypeRepo.Add(&toolType)
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

// UpdateToolType godoc
// @Summary     Update tool type by ID
// @Description Update tool type by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer         true "id" min(1)
// @Param       body body     models.ToolType true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/tool-types/{id} [put]
// @Tags        ToolType
func UpdateToolType(c *gin.Context) {
	body := models.ToolType{}
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

	toolType, err := persistence.ToolTypeRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type is not found",
		})

		return
	}

	if body.Name != "" {
		toolType.Name = body.Name
	}

	if body.Description != "" {
		toolType.Description = body.Description
	}

	err = persistence.ToolTypeRepo.Update(toolType)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// DeleteToolType godoc
// @Summary     Delete tool type by ID
// @Description Delete tool type by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/tool-types/{id} [delete]
// @Tags        ToolType
func DeleteToolType(c *gin.Context) {
	id := c.Param("id")

	toolType, err := persistence.ToolTypeRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type is not found",
		})

		return
	}

	err = persistence.ToolTypeRepo.Delete(toolType)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
