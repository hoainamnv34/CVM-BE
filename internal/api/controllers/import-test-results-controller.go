package controllers

import (
	"fmt"
	"net/http"
	"path/filepath"

	findingservice "vulnerability-management/internal/api/services/findings"
	importscan "vulnerability-management/internal/api/services/import-scan"
	pipelinerunservice "vulnerability-management/internal/api/services/pipeline-runs"
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
	ProJectID      uint64 `json:"project_id" form:"project_id"`
	CommitHash     string `json:"commit_hash" form:"commit_hash"`
	BranchName     string `json:"branch_name" form:"branch_name"`
	PipelineRunURL string `json:"pipeline_run_url" form:"pipeline_run_url"`
	PipelineRunID  uint64 `json:"pipeline_run_id" form:"pipeline_run_id"`
	ToolName       string `json:"tool_name" form:"tool_name"`
	Servicekey     string `json:"service_key" form:"service_key"`
	TestTitle      string `json:"test_title" form:"test_title"`
}

// @Summary     Import Test Result
// @Description Upload a file
// @Accept      mpfd
// @Produce     json
// @Param       project_id       query    string true  "Project ID"
// @Param       pipeline_run_id  query    string true  "Pipeline run ID from Repo"
// @Param       pipeline_run_url query    string false "Pipeline run URL from Repo"
// @Param       commit_hash      query    string false "Commit hash"
// @Param       branch_name      query    string false "Branch name"
// @Param       tool_name        query    string true  "Tool name"
// @Param       test_title       query    string true  "Test title"
// @Param       service_key      query    string false "Service key"
// @Param       file             formData file   false "file"
// @Success     200              {object} http_res.HTTPResponse
// @Failure     400              {object} http_err.HTTPError
// @Failure     500              {object} http_err.HTTPError
// @Router      /api/import [post]
func ImportTestResult(c *gin.Context) {
	query := importTestResultRequest{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	log.Info().Msgf("%v", query)

	//get piepline-run
	runs, err := pipelinerunservice.GetPipelineRuns(pipeline_runs_models.PipelineRun{
		PipelineRunID: query.PipelineRunID,
		ProjectID:     query.ProJectID,
	}, "1", "100")

	if err != nil {
		log.Error().Msgf(err.Error())
		c.JSON(http.StatusInternalServerError, http_err.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Unable to get pipeline_run"})
		return
	}

	var pipelineRun *pipeline_runs_models.PipelineRun
	if len(runs) == 0 {
		//create pipeline run
		pipelineRun, err = persistence.PipelineRunRepo.Add(&pipeline_runs_models.PipelineRun{
			ProjectID:      query.ProJectID,
			BranchName:     query.BranchName,
			CommitHash:     query.CommitHash,
			Status:         1,
			PipelineRunID:  query.PipelineRunID,
			PipelineRunURL: query.PipelineRunURL,
		})
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
				Code:    http.StatusBadRequest,
				Message: "Bad request",
			})

			return
		}

	} else if len(runs) != 1 {
		c.JSON(http.StatusInternalServerError, http_err.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: "Have many pipeline_run"})
		return
	} else {
		pipelineRun = &runs[0]
	}

	//get tool_type
	log.Info().Msgf("%v", query.ToolName)
	tooltypes, err := tooltypes.GetToolType(query.ToolName, "")
	if err != nil {
		c.JSON(http.StatusBadRequest, http_err.HTTPError{Code: http.StatusBadRequest, Message: "Not Found Test Type"})
		return
	}

	log.Info().Msgf("%v", tooltypes)

	//create test
	test, err := persistence.TestRepo.Add(&tests_models.Test{
		Name:          query.TestTitle,
		PipelineRunID: pipelineRun.ID,
		ToolTypeID:    tooltypes[0].ID,
	})
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})
		return
	}

	//Create tooltype
	factory := &importscan.Factory{}
	tool := factory.CreateTool(query.ToolName)
	if tool == nil {
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Tool %s not supported", query.ToolName),
		})

		return
	}
	// Retrieve the file from the request
	dst := ""
	if tool.RequiresFile() {
		fmt.Println("need file")
		file, err := c.FormFile("file")

		if err != nil {
			c.JSON(http.StatusBadRequest, http_err.HTTPError{Code: http.StatusBadRequest, Message: "Bad request"})
			return
		}
		// Get the filename and ensure it's a secure path
		filename := filepath.Base(file.Filename)

		// Define the destination path where the file will be saved
		dst = fmt.Sprintf("./uploads/%s", filename)

		// Save the file to the specified destination
		if err := c.SaveUploadedFile(file, dst); err != nil {
			c.JSON(http.StatusInternalServerError, http_err.HTTPError{Code: http.StatusInternalServerError, Message: "Unable to save the file"})
			return
		}
	}

	//here
	findings, err := tool.Parser(dst, query.Servicekey)

	if err != nil {
		c.JSON(http.StatusBadRequest, http_err.HTTPError{Code: http.StatusInternalServerError, Message: "Not Found Test Type"})
		return
	}

	for _, finding := range findings {
		finding.ProjectID = query.ProJectID
		err = findingservice.SolveFinding(finding, test.ID)
		if err != nil {
			log.Error().Msgf(err.Error())
			c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
				Code:    http.StatusInternalServerError,
				Message: err.Error(),
			})

			return
		}
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{Message: "File uploaded successfully!"})
}
