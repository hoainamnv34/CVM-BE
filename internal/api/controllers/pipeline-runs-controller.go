package controllers

import (
	"fmt"
	"net/http"
	"strconv"

	pipelinerunservice "vulnerability-management/internal/api/services/pipeline-runs"
	models "vulnerability-management/internal/pkg/models/pipeline-runs"
	pipeline_runs_models "vulnerability-management/internal/pkg/models/pipeline-runs"
	persistence "vulnerability-management/internal/pkg/persistence"
	helpers "vulnerability-management/pkg/helpers"
	http_err "vulnerability-management/pkg/http-err"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetPipelineRunByID godoc
// @Summary     Get pipeline run by ID
// @Description Get pipeline run by ID
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200             {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs/{id} [get]
// @Security    Authorization Token
// @Tags        PipelineRun
func GetPipelineRunByID(c *gin.Context) {
	id := c.Param("id")

	pipelineRun, err := persistence.PipelineRunRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    pipelineRun,
	})
}

// GetPipelineRuns godoc
// @Summary     Get pipeline runs by query
// @Description Get pipeline runs by query
// @Produce     json
// @Param       branch_name      query    string  false "branch_name"
// @Param       commit_hash      query    string  false "commit_hash"
// @Param       status           query    integer false "status"
// @Param       project_id       query    integer false "project_id"
// @Param       pipeline_run_url query    string  false "pipeline_run_url"
// @Param       pipeline_run_id  query    integer false "pipeline_run_id"
// @Param       page             query    integer false "page"
// @Param       size             query    integer false "size"
// @Success     200              {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs [get]
// @Security    Authorization Token
// @Tags        PipelineRun
func GetPipelineRuns(c *gin.Context) {
	query := models.PipelineRun{}

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

	if query.BranchName != "" {
		where["branch_name"] = query.BranchName
	}

	if query.CommitHash != "" {
		where["commit_hash"] = query.CommitHash
	}

	if query.Status != 0 {
		where["status"] = query.Status
	}

	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}

	if query.PipelineRunID != 0 {
		where["pipeline_run_id"] = query.PipelineRunID
	}

	if query.PipelineRunURL != "" {
		where["pipeline_run_url"] = query.PipelineRunURL
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	pipelineRuns, count, err := persistence.PipelineRunRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline runs not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      pipelineRuns,
		DataCount: count,
	})
}

// CreatePipelineRun godoc
// @Summary     Create pipeline run
// @Description Create pipeline run
// @Accept      json
// @Produce     json
// @Param       body body     models.PipelineRun true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs [post]
// @Tags        PipelineRun
func CreatePipelineRun(c *gin.Context) {
	body := models.PipelineRun{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})

		return
	}

	pipelineRun := models.PipelineRun{
		BranchName:     body.BranchName,
		CommitHash:     body.CommitHash,
		Status:         body.Status,
		ProjectID:      body.ProjectID,
		PipelineRunURL: body.PipelineRunURL,
		PipelineRunID:  body.PipelineRunID,
	}

	res, err := persistence.PipelineRunRepo.Add(&pipelineRun)
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

type evaluateRequest struct {
	ProJectID     uint64 `json:"project_id" form:"project_id"`
	PipelineRunID uint64 `json:"pipeline_run_id" form:"pipeline_run_id"`
	LatestRequest bool   `json:"latest_request" form:"latest_request"`
}

// EvaluatePipelineRun godoc
// @Summary     Evaluate pipeline run by ID
// @Description Evaluate pipeline run by ID
// @Produce     json
// @Param       project_id      query    int  true "Project ID"
// @Param       pipeline_run_id query    int  true "Pipeline run ID from Repo"
// @Param       latest_request  query    bool true "Latest Evaluation Request ?"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs/evaluate [get]
// @Security    Authorization Token
// @Tags        PipelineRun
func EvaluatePipelineRun(c *gin.Context) {
	fmt.Println("xxxx")
	query := evaluateRequest{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	fmt.Println(query)

	type Evaluate struct {
		Evaluate       bool   `json:"evaluate" form:"evaluate"`
		ThresholdScore uint64 `json:"threshold_score" form:"threshold_score"`
		Score          uint64 `json:"score" form:"score"`
	}

	//get piepline-run
	pipelineRuns, err := pipelinerunservice.GetPipelineRuns(pipeline_runs_models.PipelineRun{
		PipelineRunID: query.PipelineRunID,
		ProjectID:     query.ProJectID,
	}, "1", "100")

	pipelineRun := pipelineRuns[0]
	if err != nil {
		c.JSON(http.StatusInternalServerError, http_err.HTTPError{
			Code: http.StatusInternalServerError, 
			Message: "Unable to get pipeline_run"})
		return
	}

	project, err := persistence.ProjectRepo.Get(strconv.Itoa(int(pipelineRun.ProjectID)))
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project is not found",
		})

		return
	}

	pipelineEvaluation, err := persistence.PipelineEvaluationRepo.Get(strconv.Itoa(int(project.PipelineEvaluationID)))
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation is not found",
		})

		return
	}

	count1, err := persistence.FindingRepo.CountByPipelineRunIDAndSeverity(pipelineRun.ID, 1)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Findings not found",
		})

		return
	}

	count2, err := persistence.FindingRepo.CountByPipelineRunIDAndSeverity(pipelineRun.ID, 2)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Findings not found",
		})

		return
	}

	count3, err := persistence.FindingRepo.CountByPipelineRunIDAndSeverity(pipelineRun.ID, 3)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Findings not found",
		})

		return
	}

	count4, err := persistence.FindingRepo.CountByPipelineRunIDAndSeverity(pipelineRun.ID, 4)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Findings not found",
		})

		return
	}

	count5, err := persistence.FindingRepo.CountByPipelineRunIDAndSeverity(pipelineRun.ID, 5)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Findings not found",
		})

		return
	}

	score := count1*0 + count2*int(pipelineEvaluation.SeverityLowScore) + count3*int(pipelineEvaluation.SeverityMediumScore) + count4*int(pipelineEvaluation.SeverityHighScore) + count5*int(pipelineEvaluation.SeverityCriticalScore)

	evaluation := true

	if score > int(pipelineEvaluation.ThresholdScore) {
		evaluation = false
	}

	if query.LatestRequest == true {
		// TODO
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data: Evaluate{
			Evaluate:       evaluation,
			ThresholdScore: pipelineEvaluation.ThresholdScore,
			Score:          uint64(score),
		},
	})
}

// UpdatePipelineRun godoc
// @Summary     Update pipeline run by ID
// @Description Update pipeline run by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer            true "id" min(1)
// @Param       body body     models.PipelineRun true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs/{id} [put]
// @Tags        PipelineRun
func UpdatePipelineRun(c *gin.Context) {
	body := models.PipelineRun{}
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

	pipelineRun, err := persistence.PipelineRunRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run is not found",
		})

		return
	}

	if body.BranchName != "" {
		pipelineRun.BranchName = body.BranchName
	}

	if body.CommitHash != "" {
		pipelineRun.CommitHash = body.CommitHash
	}

	if body.Status != 0 {
		pipelineRun.Status = body.Status
	}

	if body.ProjectID != 0 {
		pipelineRun.ProjectID = body.ProjectID
	}

	if body.PipelineRunURL != "" {
		pipelineRun.PipelineRunURL = body.PipelineRunURL
	}

	if body.PipelineRunID != 0 {
		pipelineRun.PipelineRunID = body.PipelineRunID
	}

	err = persistence.PipelineRunRepo.Update(pipelineRun)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// DeletePipelineRun godoc
// @Summary     Delete pipeline run by ID
// @Description Delete pipeline run by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs/{id} [delete]
// @Tags        PipelineRun
func DeletePipelineRun(c *gin.Context) {
	id := c.Param("id")

	pipelineRun, err := persistence.PipelineRunRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run is not found",
		})

		return
	}

	err = persistence.PipelineRunRepo.Delete(pipelineRun)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
