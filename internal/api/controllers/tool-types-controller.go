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
// @Tags        ToolType
// GetToolTypeByID godoc
// @Summary     Get tool type by ID
// @Description Get tool type by ID
// @Produce     json
// @Param       id  path     integer true "ID"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/tool-types/{id} [get]
// @Tags        ToolType
func GetToolTypeByID(c *gin.Context) {
	log.Info().Msg("GetToolTypeByID initiated")

	id := c.Param("id")

	toolType, err := persistence.ToolTypeRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching tool type in GetToolTypeByID")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Tool type fetched successfully in GetToolTypeByID")
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
// @Param       name        query    string  false "Name"
// @Param       description query    string  false "Description"
// @Param       page        query    integer false "Page"
// @Param       size        query    integer false "Size"
// @Success     200         {object} http_res.HTTPResponse
// @Router      /api/tool-types [get]
// @Tags        ToolType
func GetToolTypes(c *gin.Context) {
	log.Info().Msg("GetToolTypes initiated")

	query := models.ToolType{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in GetToolTypes")
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
		Msg("Query parameters for GetToolTypes")

	toolTypes, count, err := persistence.ToolTypeRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error querying tool types in GetToolTypes")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool types not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Tool types fetched successfully in GetToolTypes")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      toolTypes,
		DataCount: count,
	})
}

// ToolTypeRequest represents the payload for creating and updating a tool type.
type ToolTypeRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

// CreateToolType godoc
// @Summary     Create tool type
// @Description Create tool type
// @Accept      json
// @Produce     json
// @Param       body body     ToolTypeRequest true "Body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/tool-types [post]
// @Tags        ToolType
func CreateToolType(c *gin.Context) {
	log.Info().Msg("CreateToolType initiated")

	var body ToolTypeRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in CreateToolType")
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
		log.Error().Err(err).Msg("Error adding tool type in CreateToolType")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})
		return
	}

	log.Info().Msg("Tool type created successfully in CreateToolType")
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
// @Param       id   path     integer         true "ID"
// @Param       body body     ToolTypeRequest true "Body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/tool-types/{id} [put]
// @Tags        ToolType
func UpdateToolType(c *gin.Context) {
	log.Info().Msg("UpdateToolType initiated")

	var body ToolTypeRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in UpdateToolType")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	id := c.Param("id")

	toolType, err := persistence.ToolTypeRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching tool type in UpdateToolType")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type not found",
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
		log.Error().Err(err).Str("id", id).Msg("Error updating tool type in UpdateToolType")
		c.JSON(http.StatusInternalServerError, http_res.HTTPResponse{
			Code:    http.StatusInternalServerError,
			Message: "Unable to update tool type",
		})
		return
	}

	log.Info().Str("id", id).Msg("Tool type updated successfully in UpdateToolType")
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
// @Param       id  path     integer true "ID"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/tool-types/{id} [delete]
// @Tags        ToolType
func DeleteToolType(c *gin.Context) {
	log.Info().Msg("DeleteToolType initiated")

	id := c.Param("id")

	toolType, err := persistence.ToolTypeRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching tool type in DeleteToolType")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type not found",
		})
		return
	}

	err = persistence.ToolTypeRepo.Delete(toolType)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error deleting tool type in DeleteToolType")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tool type not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Tool type deleted successfully in DeleteToolType")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
