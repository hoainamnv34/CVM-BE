package controllers

import (
	"fmt"
	"net/http"
	"path/filepath"

	finding_services "vulnerability-management/internal/api/services/finding"
	importscan "vulnerability-management/internal/api/services/import-scan"
	pipelinerunservice "vulnerability-management/internal/api/services/pipeline-run"
	tooltypes "vulnerability-management/internal/api/services/tool-types"
	pipeline_runs_models "vulnerability-management/internal/pkg/models/pipeline-runs"
	tests_models "vulnerability-management/internal/pkg/models/tests"
	persistence "vulnerability-management/internal/pkg/persistence"
	http_err "vulnerability-management/pkg/http-err"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type importTestResultRequest struct {
	ProJectID  uint64 `json:"project_id" form:"project_id"`
	CommitHash string `json:"commit_hash" form:"commit_hash"`
	BranchName string `json:"branch_name" form:"branch_name"`
	RunURL     string `json:"run_url" form:"run_url"`
	RunID      uint64 `json:"run_id" form:"run_id"`
	ToolName   string `json:"tool_name" form:"tool_name"`
	Servicekey string `json:"service_key" form:"service_key"`
	TestTitle  string `json:"test_title" form:"test_title"`
}

// ImportTestResult godoc
// @Summary     Import Test Result
// @Description Upload a file
// @Accept      mpfd
// @Produce     json
// @Param       project_id  query    string true  "Project ID"
// @Param       run_id      query    string true  "Run ID from CI/CD pipeline"
// @Param       run_url     query    string false "Run URL from CI/CD pipeline"
// @Param       commit_hash query    string false "Commit hash"
// @Param       branch_name query    string false "Branch name"
// @Param       tool_name   query    string true  "Tool name"
// @Param       test_title  query    string true  "Test title"
// @Param       service_key query    string false "Service key"
// @Param       file        formData file   false "file"
// @Success     200         {object} http_res.HTTPResponse
// @Failure     400         {object} http_err.HTTPError
// @Failure     500         {object} http_err.HTTPError
// @Router      /api/import [post]
func ImportTestResult(c *gin.Context) {
	log.Info().Msg("ImportTestResult initiated")

	query := importTestResultRequest{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in ImportTestResult")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	log.Info().Interface("query", query).Msg("Query parameters received in ImportTestResult")

	// Get pipeline run
	runs, _, err := pipelinerunservice.GetPipelineRuns(pipeline_runs_models.PipelineRun{
		RunID:     query.RunID,
		ProjectID: query.ProJectID,
	}, "1", "100")

	if err != nil {
		log.Error().Err(err).Msg("Error querying pipeline runs in ImportTestResult")
		c.JSON(http.StatusInternalServerError, http_err.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Unable to get pipeline_run",
		})
		return
	}

	var pipelineRun *pipeline_runs_models.PipelineRun
	if len(runs) == 0 {
		// Create pipeline run
		pipelineRun, err = persistence.PipelineRunRepo.Add(&pipeline_runs_models.PipelineRun{
			ProjectID:  query.ProJectID,
			BranchName: query.BranchName,
			CommitHash: query.CommitHash,
			Status:     1,
			RunID:      query.RunID,
			RunURL:     query.RunURL,
		})
		if err != nil {
			log.Error().Err(err).Msg("Error adding pipeline run in ImportTestResult")
			c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
				Code:    http.StatusBadRequest,
				Message: "Bad request",
			})
			return
		}
	} else if len(runs) != 1 {
		log.Error().Msg("Multiple pipeline runs found in ImportTestResult")
		c.JSON(http.StatusInternalServerError, http_err.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Multiple pipeline_runs found",
		})
		return
	} else {
		pipelineRun = &runs[0]
	}

	// Get tool type
	log.Info().Str("tool_name", query.ToolName).Msg("Fetching tool type in ImportTestResult")
	toolTypes, err := tooltypes.GetToolType(query.ToolName, "")
	if err != nil {
		log.Error().Err(err).Msg("Error fetching tool type in ImportTestResult")
		c.JSON(http.StatusBadRequest, http_err.HTTPError{
			Code:    http.StatusBadRequest,
			Message: "Tool type not found",
		})
		return
	}

	log.Info().Interface("tool_types", toolTypes).Msg("Tool types fetched in ImportTestResult")

	// Create test
	test, err := persistence.TestRepo.Add(&tests_models.Test{
		Name:          query.TestTitle,
		PipelineRunID: pipelineRun.ID,
		ToolTypeID:    toolTypes[0].ID,
	})
	if err != nil {
		log.Error().Err(err).Msg("Error adding test in ImportTestResult")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})
		return
	}

	// Create tool
	factory := &importscan.Factory{}
	tool := factory.CreateTool(query.ToolName)
	if tool == nil {
		log.Error().Msgf("Tool %s not supported", query.ToolName)
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Tool %s not supported", query.ToolName),
		})
		return
	}

	// Retrieve the file from the request
	dst := ""
	if tool.RequiresFile() {
		file, err := c.FormFile("file")
		if err != nil {
			log.Error().Err(err).Msg("Error retrieving file in ImportTestResult")
			c.JSON(http.StatusBadRequest, http_err.HTTPError{
				Code:    http.StatusBadRequest,
				Message: "Bad request",
			})
			return
		}
		// Get the filename and ensure it's a secure path
		filename := filepath.Base(file.Filename)
		// Define the destination path where the file will be saved
		dst = fmt.Sprintf("./uploads/%s", filename)
		// Save the file to the specified destination
		if err := c.SaveUploadedFile(file, dst); err != nil {
			log.Error().Err(err).Msg("Error saving file in ImportTestResult")
			c.JSON(http.StatusInternalServerError, http_err.HTTPError{
				Code:    http.StatusInternalServerError,
				Message: "Unable to save the file",
			})
			return
		}
	}

	// Parse findings
	findings, err := tool.Parser(dst, query.Servicekey)
	if err != nil {
		log.Error().Err(err).Msg("Error parsing findings in ImportTestResult")
		c.JSON(http.StatusBadRequest, http_err.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Error parsing findings",
		})
		return
	}

	for _, finding := range findings {
		finding.ProjectID = query.ProJectID
		err = finding_services.SolveFinding(finding, test.ID)
		if err != nil {
			log.Error().Err(err).Msg("Error solving finding in ImportTestResult")
			c.JSON(http.StatusInternalServerError, http_res.HTTPResponse{
				Code:    http.StatusInternalServerError,
				Message: err.Error(),
			})
			return
		}
	}

	log.Info().Msg("File uploaded and processed successfully in ImportTestResult")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "File uploaded successfully!",
	})
}
