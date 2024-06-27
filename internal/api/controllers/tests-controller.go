package controllers

import (
	"net/http"

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
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/tests/{id} [get]
// @Security    Authorization Token
// @Tags        Test
func GetTestByID(c *gin.Context) {
	id := c.Param("id")

	log.Info().Msgf("Get test by ID: %s", id)

	test, err := persistence.TestRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Test is not found",
		})

		return
	}

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
// @Param       name            query    string  false "name"
// @Param       pipeline_run_id query    integer false "pipeline_run_id"
// @Param       tool_type_id    query    integer false "tool_type_id"
// @Param       page            query    integer false "page"
// @Param       size            query    integer false "size"
// @Success     200             {object} http_res.HTTPResponse
// @Router      /api/tests [get]
// @Security    Authorization Token
// @Tags        Test
func GetTests(c *gin.Context) {
	query := models.Test{}

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

	if query.PipelineRunID != 0 {
		where["pipeline_run_id"] = query.PipelineRunID
	}

	if query.ToolTypeID != 0 {
		where["tool_type_id"] = query.ToolTypeID
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	tests, count, err := persistence.TestRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Tests not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      tests,
		DataCount: count,
	})
}

// CreateTest godoc
// @Summary     Create test
// @Description Create test
// @Accept      json
// @Produce     json
// @Param       body body     models.Test true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/tests [post]
// @Tags        Test
func CreateTest(c *gin.Context) {
	body := models.Test{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

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

// UpdateTest godoc
// @Summary     Update test by ID
// @Description Update test by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer     true "id" min(1)
// @Param       body body     models.Test true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/tests/{id} [put]
// @Tags        Test
func UpdateTest(c *gin.Context) {
	body := models.Test{}
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

	test, err := persistence.TestRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Test is not found",
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
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Test is not found",
		})

		return
	}

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
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/tests/{id} [delete]
// @Tags        Test
func DeleteTest(c *gin.Context) {
	id := c.Param("id")

	test, err := persistence.TestRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Test is not found",
		})

		return
	}

	err = persistence.TestRepo.Delete(test)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Test is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
