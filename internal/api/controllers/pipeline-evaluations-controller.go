package controllers

import (
	"net/http"

	models "vulnerability-management/internal/pkg/models/pipeline-evaluations"
	persistence "vulnerability-management/internal/pkg/persistence"
	helpers "vulnerability-management/pkg/helpers"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetPipelineEvaluationByID godoc
// @Summary     Get pipeline evaluation by ID
// @Description Get pipeline evaluation by ID
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations/{id} [get]
// @Security    Authorization Token
// @Tags        PipelineEvaluation
func GetPipelineEvaluationByID(c *gin.Context) {
	id := c.Param("id")

	pipelineEvaluation, err := persistence.PipelineEvaluationRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    pipelineEvaluation,
	})
}

// GetPipelineEvaluations godoc
// @Summary     Get pipeline evaluations by query
// @Description Get pipeline evaluations by query
// @Produce     json
// @Param       severity_critical_score query    integer false "severity_critical_score"
// @Param       severity_high_score     query    integer false "severity_high_score"
// @Param       severity_medium_score   query    integer false "severity_medium_score"
// @Param       severity_low_score      query    integer false "severity_low_score"
// @Param       threshold_score         query    integer false "threshold_score"
// @Param       page                    query    integer false "page"
// @Param       size                    query    integer false "size"
// @Success     200                     {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations [get]
// @Security    Authorization Token
// @Tags        PipelineEvaluation
func GetPipelineEvaluations(c *gin.Context) {
	query := models.PipelineEvaluation{}

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

	if query.SeverityCriticalScore != 0 {
		where["severity_critical_score"] = query.SeverityCriticalScore
	}

	if query.SeverityHighScore != 0 {
		where["severity_high_score"] = query.SeverityHighScore
	}

	if query.SeverityMediumScore != 0 {
		where["severity_medium_score"] = query.SeverityMediumScore
	}

	if query.SeverityLowScore != 0 {
		where["severity_low_score"] = query.SeverityLowScore
	}

	if query.ThresholdScore != 0 {
		where["threshold_score"] = query.ThresholdScore
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	pipelineEvaluations, count, err := persistence.PipelineEvaluationRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluations not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      pipelineEvaluations,
		DataCount: count,
	})
}

// CountPipelineEvaluations godoc
// @Summary     Count pipeline evaluations by query
// @Description Count pipeline evaluations by query
// @Produce     json
// @Param       severity_critical_score query    integer false "severity_critical_score"
// @Param       severity_high_score     query    integer false "severity_high_score"
// @Param       severity_medium_score   query    integer false "severity_medium_score"
// @Param       severity_low_score      query    integer false "severity_low_score"
// @Param       threshold_score         query    integer false "threshold_score"
// @Success     200                     {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations/count [get]
// @Security    Authorization Token
// @Tags        PipelineEvaluation
func CountPipelineEvaluations(c *gin.Context) {
	query := models.PipelineEvaluation{}

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

	if query.SeverityCriticalScore != 0 {
		where["severity_critical_score"] = query.SeverityCriticalScore
	}

	if query.SeverityHighScore != 0 {
		where["severity_high_score"] = query.SeverityHighScore
	}

	if query.SeverityMediumScore != 0 {
		where["severity_medium_score"] = query.SeverityMediumScore
	}

	if query.SeverityLowScore != 0 {
		where["severity_low_score"] = query.SeverityLowScore
	}

	if query.ThresholdScore != 0 {
		where["threshold_score"] = query.ThresholdScore
	}

	count, err := persistence.PipelineEvaluationRepo.Count(where)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluations not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    count,
	})
}

// CreatePipelineEvaluation godoc
// @Summary     Create pipeline evaluation
// @Description Create pipeline evaluation
// @Accept      json
// @Produce     json
// @Param       body body     models.PipelineEvaluation true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations [post]
// @Tags        PipelineEvaluation
func CreatePipelineEvaluation(c *gin.Context) {
	body := models.PipelineEvaluation{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})

		return
	}

	pipelineEvaluation := models.PipelineEvaluation{
		SeverityCriticalScore: body.SeverityCriticalScore,
		SeverityHighScore:     body.SeverityHighScore,
		SeverityMediumScore:   body.SeverityMediumScore,
		SeverityLowScore:      body.SeverityLowScore,
		ThresholdScore:        body.ThresholdScore,
	}

	res, err := persistence.PipelineEvaluationRepo.Add(&pipelineEvaluation)
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

// UpdatePipelineEvaluation godoc
// @Summary     Update pipeline evaluation by ID
// @Description Update pipeline evaluation by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer                   true "id" min(1)
// @Param       body body     models.PipelineEvaluation true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations/{id} [put]
// @Tags        PipelineEvaluation
func UpdatePipelineEvaluation(c *gin.Context) {
	body := models.PipelineEvaluation{}
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

	pipelineEvaluation, err := persistence.PipelineEvaluationRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation is not found",
		})

		return
	}

	if body.SeverityCriticalScore != 0 {
		pipelineEvaluation.SeverityCriticalScore = body.SeverityCriticalScore
	}

	if body.SeverityHighScore != 0 {
		pipelineEvaluation.SeverityHighScore = body.SeverityHighScore
	}

	if body.SeverityMediumScore != 0 {
		pipelineEvaluation.SeverityMediumScore = body.SeverityMediumScore
	}

	if body.SeverityLowScore != 0 {
		pipelineEvaluation.SeverityLowScore = body.SeverityLowScore
	}

	if body.ThresholdScore != 0 {
		pipelineEvaluation.ThresholdScore = body.ThresholdScore
	}

	err = persistence.PipelineEvaluationRepo.Update(pipelineEvaluation)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// DeletePipelineEvaluation godoc
// @Summary     Delete pipeline evaluation by ID
// @Description Delete pipeline evaluation by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations/{id} [delete]
// @Tags        PipelineEvaluation
func DeletePipelineEvaluation(c *gin.Context) {
	id := c.Param("id")

	pipelineEvaluation, err := persistence.PipelineEvaluationRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation is not found",
		})

		return
	}

	err = persistence.PipelineEvaluationRepo.Delete(pipelineEvaluation)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
