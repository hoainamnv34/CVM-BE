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
// @Param       id  path     integer true "ID"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations/{id} [get]
// @Tags        PipelineEvaluation
func GetPipelineEvaluationByID(c *gin.Context) {
	log.Info().Msg("GetPipelineEvaluationByID initiated")

	id := c.Param("id")

	pipelineEvaluation, err := persistence.PipelineEvaluationRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching pipeline evaluation in GetPipelineEvaluationByID")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Pipeline evaluation fetched successfully in GetPipelineEvaluationByID")
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
// @Param       severity_critical_score query    integer false "Severity Critical Score"
// @Param       severity_high_score     query    integer false "Severity High Score"
// @Param       severity_medium_score   query    integer false "Severity Medium Score"
// @Param       severity_low_score      query    integer false "Severity Low Score"
// @Param       threshold_score         query    integer false "Threshold Score"
// @Param       page                    query    integer false "Page"
// @Param       size                    query    integer false "Size"
// @Success     200                     {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations [get]
// @Tags        PipelineEvaluation
func GetPipelineEvaluations(c *gin.Context) {
	log.Info().Msg("GetPipelineEvaluations initiated")

	query := models.PipelineEvaluation{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in GetPipelineEvaluations")
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
	log.Info().
		Interface("where", where).
		Int("offset", offset).
		Int("limit", limit).
		Msg("Query parameters for GetPipelineEvaluations")

	pipelineEvaluations, count, err := persistence.PipelineEvaluationRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error querying pipeline evaluations in GetPipelineEvaluations")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluations not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Pipeline evaluations fetched successfully in GetPipelineEvaluations")
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
// @Param       severity_critical_score query    integer false "Severity Critical Score"
// @Param       severity_high_score     query    integer false "Severity High Score"
// @Param       severity_medium_score   query    integer false "Severity Medium Score"
// @Param       severity_low_score      query    integer false "Severity Low Score"
// @Param       threshold_score         query    integer false "Threshold Score"
// @Success     200                     {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations/count [get]
// @Tags        PipelineEvaluation
func CountPipelineEvaluations(c *gin.Context) {
	log.Info().Msg("CountPipelineEvaluations initiated")

	query := models.PipelineEvaluation{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in CountPipelineEvaluations")
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
		log.Error().Err(err).Msg("Error counting pipeline evaluations in CountPipelineEvaluations")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluations not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Pipeline evaluations counted successfully in CountPipelineEvaluations")
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
	log.Info().Msg("CreatePipelineEvaluation initiated")

	body := models.PipelineEvaluation{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in CreatePipelineEvaluation")
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
		log.Error().Err(err).Msg("Error adding pipeline evaluation in CreatePipelineEvaluation")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})
		return
	}

	log.Info().Msg("Pipeline evaluation created successfully in CreatePipelineEvaluation")
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
// @Param       id   path     integer                   true "ID"
// @Param       body body     models.PipelineEvaluation true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations/{id} [put]
// @Tags        PipelineEvaluation
func UpdatePipelineEvaluation(c *gin.Context) {
	log.Info().Msg("UpdatePipelineEvaluation initiated")

	body := models.PipelineEvaluation{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in UpdatePipelineEvaluation")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	id := c.Param("id")

	pipelineEvaluation, err := persistence.PipelineEvaluationRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching pipeline evaluation in UpdatePipelineEvaluation")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation not found",
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
		log.Error().Err(err).Str("id", id).Msg("Error updating pipeline evaluation in UpdatePipelineEvaluation")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Pipeline evaluation updated successfully in UpdatePipelineEvaluation")
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
// @Param       id  path     integer true "ID"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/pipeline-evaluations/{id} [delete]
// @Tags        PipelineEvaluation
func DeletePipelineEvaluation(c *gin.Context) {
	log.Info().Msg("DeletePipelineEvaluation initiated")

	id := c.Param("id")

	pipelineEvaluation, err := persistence.PipelineEvaluationRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching pipeline evaluation in DeletePipelineEvaluation")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation not found",
		})
		return
	}

	err = persistence.PipelineEvaluationRepo.Delete(pipelineEvaluation)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error deleting pipeline evaluation in DeletePipelineEvaluation")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Pipeline evaluation deleted successfully in DeletePipelineEvaluation")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
