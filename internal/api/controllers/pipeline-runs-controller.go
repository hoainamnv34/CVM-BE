package controllers

import (
	"net/http"
	"strconv"

	pipeline_run_services "vulnerability-management/internal/api/services/pipeline-run"
	models "vulnerability-management/internal/pkg/models/pipeline-runs"
	pipeline_runs_models "vulnerability-management/internal/pkg/models/pipeline-runs"
	persistence "vulnerability-management/internal/pkg/persistence"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetPipelineRunByID godoc
// @Summary     Get pipeline run by ID
// @Description Get pipeline run by ID
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200           {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs/{id} [get]
// @Tags        PipelineRun
func GetPipelineRunByID(c *gin.Context) {
	log.Info().Msg("GetPipelineRunByID initiated")

	id := c.Param("id")

	pipelineRun, err := persistence.PipelineRunRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching pipeline run in GetPipelineRunByID")

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run is not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Pipeline run fetched successfully in GetPipelineRunByID")
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
// @Param       branch_name query    string  false "branch_name"
// @Param       commit_hash query    string  false "commit_hash"
// @Param       status      query    integer false "status"
// @Param       project_id  query    integer false "project_id"
// @Param       run_url     query    string  false "run_url"
// @Param       run_id      query    integer false "run_id"
// @Param       page        query    integer false "page"
// @Param       size        query    integer false "size"
// @Success     200         {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs [get]
// @Tags        PipelineRun
func GetPipelineRuns(c *gin.Context) {
	log.Info().Msg("GetPipelineRuns initiated")

	query := models.PipelineRun{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in GetPipelineRuns")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	pipelineRuns, count, err := pipeline_run_services.GetPipelineRuns(query, c.Query("page"), c.Query("size"))
	if err != nil {
		log.Error().Err(err).Msg("Error querying pipeline runs in GetPipelineRuns")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline runs not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Pipeline runs fetched successfully in GetPipelineRuns")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      pipelineRuns,
		DataCount: count,
	})
}

// PipelineRunRequest represents the payload for creating and updating a pipeline run.
type PipelineRunRequest struct {
	BranchName string `json:"branch_name" binding:"required"`
	CommitHash string `json:"commit_hash" binding:"required"`
	Status     uint64 `json:"status" binding:"required"`
	ProjectID  uint64 `json:"project_id" binding:"required"`
	RunURL     string `json:"run_url"`
	RunID      uint64 `json:"run_id" binding:"required"`
}

// CreatePipelineRun godoc
// @Summary     Create pipeline run
// @Description Create pipeline run
// @Accept      json
// @Produce     json
// @Param       body body     PipelineRunRequest true "Body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs [post]
// @Tags        PipelineRun
func CreatePipelineRun(c *gin.Context) {
	log.Info().Msg("CreatePipelineRun initiated")

	var body PipelineRunRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in CreatePipelineRun")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	pipelineRun := models.PipelineRun{
		BranchName: body.BranchName,
		CommitHash: body.CommitHash,
		Status:     body.Status,
		ProjectID:  body.ProjectID,
		RunURL:     body.RunURL,
		RunID:      body.RunID,
	}

	res, err := persistence.PipelineRunRepo.Add(&pipelineRun)
	if err != nil {
		log.Error().Err(err).Msg("Error adding pipeline run in CreatePipelineRun")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})
		return
	}

	log.Info().Msg("Pipeline run created successfully in CreatePipelineRun")
	c.JSON(http.StatusCreated, http_res.HTTPResponse{
		Code:    http.StatusCreated,
		Message: "Success",
		Data:    res,
	})
}

// UpdatePipelineRun godoc
// @Summary     Update pipeline run by ID
// @Description Update pipeline run by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer            true "ID"
// @Param       body body     PipelineRunRequest true "Body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs/{id} [put]
// @Tags        PipelineRun
func UpdatePipelineRun(c *gin.Context) {
	log.Info().Msg("UpdatePipelineRun initiated")

	var body PipelineRunRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in UpdatePipelineRun")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	id := c.Param("id")
	pipelineRun, err := persistence.PipelineRunRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching pipeline run in UpdatePipelineRun")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run not found",
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
	if body.RunURL != "" {
		pipelineRun.RunURL = body.RunURL
	}
	if body.RunID != 0 {
		pipelineRun.RunID = body.RunID
	}

	err = persistence.PipelineRunRepo.Update(pipelineRun)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error updating pipeline run in UpdatePipelineRun")
		c.JSON(http.StatusInternalServerError, http_res.HTTPResponse{
			Code:    http.StatusInternalServerError,
			Message: "Unable to update pipeline run",
		})
		return
	}

	log.Info().Str("id", id).Msg("Pipeline run updated successfully in UpdatePipelineRun")
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
	log.Info().Msg("DeletePipelineRun initiated")

	id := c.Param("id")
	pipelineRun, err := persistence.PipelineRunRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching pipeline run in DeletePipelineRun")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run is not found",
		})
		return
	}

	err = pipeline_run_services.DeletePipelineRun(strconv.FormatUint(pipelineRun.ID, 10))
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error deleting pipeline run in DeletePipelineRun")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: err.Error(),
		})
		return
	}

	log.Info().Str("id", id).Msg("Pipeline run deleted successfully in DeletePipelineRun")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

type evaluateRequest struct {
	ProjectID    uint64 `json:"project_id" form:"project_id"`
	RunID        uint64 `json:"run_id" form:"run_id"`
	FinalRequest bool   `json:"final_request" form:"final_request"`
}

// EvaluatePipelineRun godoc
// @Summary     Evaluate pipeline run by ID
// @Description Evaluate pipeline run by ID
// @Produce     json
// @Param       project_id    query    int  true "Project ID"
// @Param       run_id        query    int  true "Run ID from CI/CD pipeline"
// @Param       final_request query    bool true "Final Evaluation Request?"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/pipeline-runs/evaluate [get]
// @Tags        PipelineRun
func EvaluatePipelineRun(c *gin.Context) {
	log.Info().Msg("EvaluatePipelineRun initiated")

	query := evaluateRequest{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in EvaluatePipelineRun")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	log.Info().Interface("query", query).Msg("Query parameters received in EvaluatePipelineRun")

	type Evaluate struct {
		Evaluate       bool   `json:"evaluate" form:"evaluate"`
		ThresholdScore uint64 `json:"threshold_score" form:"threshold_score"`
		Score          uint64 `json:"score" form:"score"`
	}

	// Get pipeline run
	pipelineRuns, _, err := pipeline_run_services.GetPipelineRuns(pipeline_runs_models.PipelineRun{
		RunID:     query.RunID,
		ProjectID: query.ProjectID,
	}, "1", "100")

	if err != nil {
		log.Error().Err(err).Msg("Error querying pipeline runs in EvaluatePipelineRun")
		c.JSON(http.StatusInternalServerError, http_res.HTTPResponse{
			Code:    http.StatusInternalServerError,
			Message: "Unable to get pipeline_run",
		})
		return
	}

	if len(pipelineRuns) == 0 {
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline run not found",
		})
		return
	}

	pipelineRun := pipelineRuns[0]

	project, err := persistence.ProjectRepo.Get(strconv.Itoa(int(pipelineRun.ProjectID)))
	if err != nil {
		log.Error().Err(err).Msg("Error fetching project in EvaluatePipelineRun")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Project not found",
		})
		return
	}

	pipelineEvaluation, err := persistence.PipelineEvaluationRepo.Get(strconv.Itoa(int(project.PipelineEvaluationID)))
	if err != nil {
		log.Error().Err(err).Msg("Error fetching pipeline evaluation in EvaluatePipelineRun")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Pipeline evaluation not found",
		})
		return
	}

	counts := make(map[int]int)
	severities := []int{1, 2, 3, 4, 5}
	for _, severity := range severities {
		count, err := persistence.FindingRepo.CountByPipelineRunIDAndSeverity(pipelineRun.ID, uint64(severity))
		if err != nil {
			log.Error().Err(err).Int("severity", severity).Msg("Error counting findings in EvaluatePipelineRun")
			c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
				Code:    http.StatusBadRequest,
				Message: "Findings not found",
			})
			return
		}
		counts[severity] = count
	}

	score := counts[2]*int(pipelineEvaluation.SeverityLowScore) +
		counts[3]*int(pipelineEvaluation.SeverityMediumScore) +
		counts[4]*int(pipelineEvaluation.SeverityHighScore) +
		counts[5]*int(pipelineEvaluation.SeverityCriticalScore)

	evaluation := score <= int(pipelineEvaluation.ThresholdScore)

	if query.FinalRequest {
		// TODO: Handle final request logic
	}

	log.Info().Bool("evaluation", evaluation).Int("score", score).Msg("Pipeline run evaluated successfully in EvaluatePipelineRun")
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
