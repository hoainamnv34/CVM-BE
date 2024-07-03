package controllers

import (
	"net/http"
	test_services "vulnerability-management/internal/api/services/test"

	models "vulnerability-management/internal/pkg/models/tests"
	persistence "vulnerability-management/internal/pkg/persistence"
	helpers "vulnerability-management/pkg/helpers"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetTestByID godoc
// @Summary     Get test by ID
// @Description Get test by ID
// @Produce     json
// @Param       id  path     integer true "ID"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/tests/{id} [get]
// @Security    Authorization Token
// @Tags        Test
func GetTestByID(c *gin.Context) {
	log.Info().Msg("GetTestByID initiated")

	id := c.Param("id")
	log.Info().Str("id", id).Msg("Get test by ID")

	test, err := persistence.TestRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching test in GetTestByID")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Test not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Test fetched successfully in GetTestByID")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    test,
	})
}

// GetTests godoc
// @Summary     Get tests by query
// @Description Get tests by query
// @Produce     json
// @Param       name            query    string  false "Name"
// @Param       pipeline_run_id query    integer false "Pipeline Run ID"
// @Param       tool_type_id    query    integer false "Tool Type ID"
// @Param       page            query    integer false "Page"
// @Param       size            query    integer false "Size"
// @Success     200             {object} http_res.HTTPResponse
// @Router      /api/tests [get]
// @Security    Authorization Token
// @Tags        Test
func GetTests(c *gin.Context) {
	log.Info().Msg("GetTests initiated")

	query := models.Test{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in GetTests")
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
	if query.PipelineRunID != 0 {
		where["pipeline_run_id"] = query.PipelineRunID
	}
	if query.ToolTypeID != 0 {
		where["tool_type_id"] = query.ToolTypeID
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))
	log.Info().
		Interface("where", where).
		Int("offset", offset).
		Int("limit", limit).
		Msg("Query parameters for GetTests")

	tests, count, err := persistence.TestRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error querying tests in GetTests")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tests not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Tests fetched successfully in GetTests")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      tests,
		DataCount: count,
	})
}

// TestRequest represents the payload for creating and updating a test.
type TestRequest struct {
	Name          string `json:"name" binding:"required"`
	PipelineRunID uint64 `json:"pipeline_run_id" binding:"required"`
	ToolTypeID    uint64 `json:"tool_type_id" binding:"required"`
}

// CreateTest godoc
// @Summary     Create test
// @Description Create test
// @Accept      json
// @Produce     json
// @Param       body body     TestRequest true "Body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/tests [post]
// @Tags        Test
func CreateTest(c *gin.Context) {
	log.Info().Msg("CreateTest initiated")

	var body TestRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in CreateTest")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	test := models.Test{
		Name:          body.Name,
		PipelineRunID: body.PipelineRunID,
		ToolTypeID:    body.ToolTypeID,
	}

	res, err := persistence.TestRepo.Add(&test)
	if err != nil {
		log.Error().Err(err).Msg("Error adding test in CreateTest")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})
		return
	}

	log.Info().Msg("Test created successfully in CreateTest")
	c.JSON(http.StatusCreated, http_res.HTTPResponse{
		Code:    http.StatusCreated,
		Message: "Success",
		Data:    res,
	})
}

// UpdateTest godoc
// @Summary     Update test by ID
// @Description Update test by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer     true "ID"
// @Param       body body     TestRequest true "Body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/tests/{id} [put]
// @Tags        Test
func UpdateTest(c *gin.Context) {
	log.Info().Msg("UpdateTest initiated")

	var body TestRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in UpdateTest")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	id := c.Param("id")

	test, err := persistence.TestRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching test in UpdateTest")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Test not found",
		})
		return
	}

	if body.Name != "" {
		test.Name = body.Name
	}
	if body.PipelineRunID != 0 {
		test.PipelineRunID = body.PipelineRunID
	}
	if body.ToolTypeID != 0 {
		test.ToolTypeID = body.ToolTypeID
	}

	err = persistence.TestRepo.Update(test)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error updating test in UpdateTest")
		c.JSON(http.StatusInternalServerError, http_res.HTTPResponse{
			Code:    http.StatusInternalServerError,
			Message: "Unable to update test",
		})
		return
	}

	log.Info().Str("id", id).Msg("Test updated successfully in UpdateTest")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// DeleteTest godoc
// @Summary     Delete test by ID
// @Description Delete test by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "ID"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/tests/{id} [delete]
// @Tags        Test
func DeleteTest(c *gin.Context) {
	log.Info().Msg("DeleteTest initiated")

	id := c.Param("id")

	err := test_services.DeleteTest(id)
	if err != nil {
		log.Error().Err(err).Msg("Error deleting test in DeleteTest")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: err.Error(),
		})
		return
	}

	log.Info().Msg("Test deleted successfully in DeleteTest")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
