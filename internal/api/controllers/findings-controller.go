package controllers

import (
	"net/http"
	"strconv"

	finding_services "vulnerability-management/internal/api/services/finding"
	models "vulnerability-management/internal/pkg/models/findings"
	persistence "vulnerability-management/internal/pkg/persistence"
	helpers "vulnerability-management/pkg/helpers"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// GetFindingByID godoc
// @Summary     Get finding by ID
// @Description Get finding by ID
// @Produce     json
// @Param       id  path     integer true "ID"
// @Success     200               {object} http_res.HTTPResponse
// @Router      /api/findings/{id} [get]
// @Tags        Finding
func GetFindingByID(c *gin.Context) {
	log.Info().Msg("GetFindingByID initiated")

	id := c.Param("id")
	log.Info().Str("id", id).Msg("Fetching finding by ID")

	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Str("id", id).Msg("Error fetching finding in GetFindingByID")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding not found",
		})
		return
	}

	log.Info().Str("id", id).Msg("Finding fetched successfully in GetFindingByID")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    finding,
	})
}

// GetFindings godoc
// @Summary     Get findings by query
// @Description Get findings by query
// @Produce     json
// @Param       project_id        query    integer false "project_id"
// @Param       title             query    string  false "title"
// @Param       description       query    string  false "description"
// @Param       severity          query    integer false "severity"
// @Param       cwe               query    integer false "cwe"
// @Param       line              query    integer false "line"
// @Param       file_path         query    string  false "file_path"
// @Param       vuln_id_from_tool query    string  false "vuln_id_from_tool"
// @Param       mitigation        query    string  false "mitigation"
// @Param       reference         query    string  false "reference"
// @Param       active            query    bool    false "active"
// @Param       dynamic_finding   query    bool    false "dynamic_finding"
// @Param       duplicate         query    bool    false "duplicate"
// @Param       risk_accepted     query    bool    false "risk_accepted"
// @Param       static_finding    query    bool    false "static_finding"
// @Param       page              query    integer false "page"
// @Param       size              query    integer false "size"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/findings [get]
// @Security    Authorization Token
// @Tags        Finding
func GetFindings(c *gin.Context) {
	log.Info().Msg("GetFindings initiated")

	query := models.Finding{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in GetFindings")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	where := map[string]interface{}{}
	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}
	if query.Title != "" {
		where["title"] = query.Title
	}
	if query.Description != "" {
		where["description"] = query.Description
	}
	if query.Severity != 0 {
		where["severity"] = query.Severity
	}
	if query.CWE != 0 {
		where["cwe"] = query.CWE
	}
	if query.Line != 0 {
		where["line"] = query.Line
	}
	if query.FilePath != "" {
		where["file_path"] = query.FilePath
	}
	if query.VulnIDFromTool != "" {
		where["vuln_id_from_tool"] = query.VulnIDFromTool
	}
	if query.Mitigation != "" {
		where["mitigation"] = query.Mitigation
	}
	if query.Reference != "" {
		where["reference"] = query.Reference
	}
	if c.Query("active") == "false" {
		where["active"] = false
	} else if c.Query("active") == "true" {
		where["active"] = true
	}
	if c.Query("dynamic_finding") == "false" {
		where["dynamic_finding"] = false
	} else if c.Query("dynamic_finding") == "true" {
		where["dynamic_finding"] = true
	}
	if c.Query("duplicate") == "false" {
		where["duplicate"] = false
	} else if c.Query("duplicate") == "true" {
		where["duplicate"] = true
	}
	if c.Query("risk_accepted") == "false" {
		where["risk_accepted"] = false
	} else if c.Query("risk_accepted") == "true" {
		where["risk_accepted"] = true
	}
	if c.Query("static_finding") == "false" {
		where["static_finding"] = false
	} else if c.Query("static_finding") == "true" {
		where["static_finding"] = true
	}

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))
	log.Info().
		Interface("where", where).
		Int("offset", offset).
		Int("limit", limit).
		Msg("Query parameters for GetFindings")

	findings, count, err := persistence.FindingRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Err(err).Msg("Error querying findings in GetFindings")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Findings not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Findings fetched successfully in GetFindings")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      findings,
		DataCount: count,
	})
}

// GetFindingsByParent godoc
// @Summary     Get findings by query parent
// @Description Get findings by query parent
// @Produce     json
// @Param       parent_id   query    integer false "Parent ID"
// @Param       parent_type query    integer false "Parent Type"
// @Param       page        query    integer false "Page"
// @Param       size        query    integer false "Size"
// @Success     200         {object} http_res.HTTPResponse
// @Router      /api/findings/parent [get]
// @Security    Authorization Token
// @Tags        Finding
func GetFindingsByParent(c *gin.Context) {
	log.Info().Msg("GetFindingsByParent initiated")

	query := struct {
		ParentID   uint64 `json:"parent_id" form:"parent_id"`
		ParentType uint64 `json:"parent_type" form:"parent_type"`
	}{}

	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in GetFindingsByParent")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	var findings *[]models.Finding
	var count int
	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	switch query.ParentType {
	case 1:
		projectGroup, err := persistence.ProjectGroupRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Err(err).Msg("Error fetching project group in GetFindingsByParent")
			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Project group not found",
			})
			return
		}

		findings, count, err = persistence.FindingRepo.QueryByProjectGroupID(projectGroup.ID, offset, limit)

	case 2:
		project, err := persistence.ProjectRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Err(err).Msg("Error fetching project in GetFindingsByParent")
			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Project not found",
			})
			return
		}

		findings, count, err = persistence.FindingRepo.QueryByProjectID(project.ID, offset, limit)
	case 3:
		pipelineRun, err := persistence.PipelineRunRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Err(err).Msg("Error fetching pipeline run in GetFindingsByParent")
			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Pipeline run not found",
			})
			return
		}

		findings, count, err = persistence.FindingRepo.QueryByPipelineRunID(pipelineRun.ID, offset, limit)
	case 4:
		test, err := persistence.TestRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Err(err).Msg("Error fetching test in GetFindingsByParent")
			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Test not found",
			})
			return
		}

		findings, count, err = persistence.FindingRepo.QueryByTestID(test.ID, offset, limit)
	default:
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	if err != nil {
		log.Error().Err(err).Msg("Error querying findings in GetFindingsByParent")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Findings not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Findings fetched successfully in GetFindingsByParent")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      findings,
		DataCount: count,
	})
}

// CountFindingsByParent godoc
// @Summary     Count findings by query parent
// @Description Count findings by query parent
// @Produce     json
// @Param       parent_id   query    integer false "Parent ID"
// @Param       parent_type query    integer false "Parent Type"
// @Success     200         {object} http_res.HTTPResponse
// @Router      /api/findings/parent/count [get]
// @Security    Authorization Token
// @Tags        Finding
func CountFindingsByParent(c *gin.Context) {
	log.Info().Msg("CountFindingsByParent initiated")

	query := struct {
		ParentID   uint64 `json:"parent_id" form:"parent_id"`
		ParentType uint64 `json:"parent_type" form:"parent_type"`
	}{}

	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in CountFindingsByParent")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	var count int
	switch query.ParentType {
	case 1:
		projectGroup, err := persistence.ProjectGroupRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Err(err).Msg("Error fetching project group in CountFindingsByParent")
			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Project group not found",
			})
			return
		}

		count, err = persistence.FindingRepo.CountByProjectGroupID(projectGroup.ID)
	case 2:
		project, err := persistence.ProjectRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Err(err).Msg("Error fetching project in CountFindingsByParent")
			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Project not found",
			})
			return
		}

		count, err = persistence.FindingRepo.CountByProjectID(project.ID)
	case 3:
		pipelineRun, err := persistence.PipelineRunRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Err(err).Msg("Error fetching pipeline run in CountFindingsByParent")
			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Pipeline run not found",
			})
			return
		}

		count, err = persistence.FindingRepo.CountByPipelineRunID(pipelineRun.ID)
	case 4:
		test, err := persistence.TestRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Err(err).Msg("Error fetching test in CountFindingsByParent")
			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Test not found",
			})
			return
		}

		count, err = persistence.FindingRepo.CountByTestID(test.ID)
	default:
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	if err != nil {
		log.Error().Err(err).Msg("Error counting findings in CountFindingsByParent")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Findings not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Findings counted successfully in CountFindingsByParent")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    count,
	})
}

// CountFindings godoc
// @Summary     Count findings by query
// @Description Count findings by query
// @Produce     json
// @Param       project_id        query    integer false "Project ID"
// @Param       title             query    string  false "Title"
// @Param       severity          query    integer false "Severity"
// @Param       cwe               query    integer false "CWE"
// @Param       line              query    integer false "Line"
// @Param       file_path         query    string  false "File Path"
// @Param       vuln_id_from_tool query    string  false "Vuln ID from Tool"
// @Param       mitigation        query    string  false "Mitigation"
// @Param       reference         query    string  false "Reference"
// @Param       reviewer          query    integer false "Reviewer"
// @Param       active            query    bool    false "Active"
// @Param       dynamic_finding   query    bool    false "Dynamic Finding"
// @Param       duplicate         query    bool    false "Duplicate"
// @Param       risk_accepted     query    bool    false "Risk Accepted"
// @Param       static_finding    query    bool    false "Static Finding"
// @Success     200               {object} http_res.HTTPResponse
// @Router      /api/findings/count [get]
// @Security    Authorization Token
// @Tags        Finding
func CountFindings(c *gin.Context) {
	log.Info().Msg("CountFindings initiated")

	query := models.Finding{}
	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Err(err).Msg("Error binding query parameters in CountFindings")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})
		return
	}

	where := map[string]interface{}{}
	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}
	if query.Title != "" {
		where["title"] = query.Title
	}
	if query.Description != "" {
		where["description"] = query.Description
	}
	if query.Severity != 0 {
		where["severity"] = query.Severity
	}
	if query.CWE != 0 {
		where["cwe"] = query.CWE
	}
	if query.Line != 0 {
		where["line"] = query.Line
	}
	if query.FilePath != "" {
		where["file_path"] = query.FilePath
	}
	if query.VulnIDFromTool != "" {
		where["vuln_id_from_tool"] = query.VulnIDFromTool
	}
	if query.Mitigation != "" {
		where["mitigation"] = query.Mitigation
	}
	if query.Reference != "" {
		where["reference"] = query.Reference
	}
	if c.Query("active") == "false" {
		where["active"] = false
	} else if c.Query("active") == "true" {
		where["active"] = true
	}
	if c.Query("dynamic_finding") == "false" {
		where["dynamic_finding"] = false
	} else if c.Query("dynamic_finding") == "true" {
		where["dynamic_finding"] = true
	}
	if c.Query("verified") == "false" {
		where["verified"] = false
	} else if c.Query("verified") == "true" {
		where["verified"] = true
	}
	if c.Query("false_p") == "false" {
		where["false_p"] = false
	} else if c.Query("false_p") == "true" {
		where["false_p"] = true
	}
	if c.Query("duplicate") == "false" {
		where["duplicate"] = false
	} else if c.Query("duplicate") == "true" {
		where["duplicate"] = true
	}
	if c.Query("risk_accepted") == "false" {
		where["risk_accepted"] = false
	} else if c.Query("risk_accepted") == "true" {
		where["risk_accepted"] = true
	}
	if c.Query("static_finding") == "false" {
		where["static_finding"] = false
	} else if c.Query("static_finding") == "true" {
		where["static_finding"] = true
	}

	count, err := persistence.FindingRepo.Count(where)
	if err != nil {
		log.Error().Err(err).Msg("Error counting findings in CountFindings")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Findings not found",
		})
		return
	}

	log.Info().Int("count", count).Msg("Findings counted successfully in CountFindings")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    count,
	})
}

// FindingRequest represents the payload for creating and updating a finding.
type FindingRequest struct {
	ProjectID      uint64 `json:"project_id" binding:"required"`
	Title          string `json:"title" binding:"required"`
	Description    string `json:"description"`
	Severity       uint64 `json:"severity" binding:"required"`
	CWE            uint64 `json:"cwe"`
	Line           uint64 `json:"line"`
	FilePath       string `json:"file_path"`
	VulnIDFromTool string `json:"vuln_id_from_tool"`
	Mitigation     string `json:"mitigation"`
	Reference      string `json:"reference"`
	Active         bool   `json:"active"`
	DynamicFinding bool   `json:"dynamic_finding"`
	Duplicate      bool   `json:"duplicate"`
	RiskAccepted   bool   `json:"risk_accepted"`
	StaticFinding  bool   `json:"static_finding"`
}

// CreateFinding godoc
// @Summary     Create finding
// @Description Create finding
// @Accept      json
// @Produce     json
// @Param       body body     FindingRequest true "Body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/findings [post]
// @Tags        Finding
func CreateFinding(c *gin.Context) {
	log.Info().Msg("CreateFinding initiated")

	var body FindingRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in CreateFinding")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	finding := models.Finding{
		ProjectID:      body.ProjectID,
		Title:          body.Title,
		Description:    body.Description,
		Severity:       body.Severity,
		CWE:            body.CWE,
		Line:           body.Line,
		FilePath:       body.FilePath,
		VulnIDFromTool: body.VulnIDFromTool,
		Mitigation:     body.Mitigation,
		Reference:      body.Reference,
		Active:         body.Active,
		DynamicFinding: body.DynamicFinding,
		Duplicate:      body.Duplicate,
		RiskAccepted:   body.RiskAccepted,
		StaticFinding:  body.StaticFinding,
	}

	res, err := persistence.FindingRepo.Add(&finding)
	if err != nil {
		log.Error().Err(err).Msg("Error adding finding in CreateFinding")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Bad request",
		})
		return
	}

	log.Info().Msg("Finding created successfully in CreateFinding")
	c.JSON(http.StatusCreated, http_res.HTTPResponse{
		Code:    http.StatusCreated,
		Message: "Success",
		Data:    res,
	})
}

// UpdateFinding godoc
// @Summary     Update finding by ID
// @Description Update finding by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer        true "ID"
// @Param       body body     FindingRequest true "Body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/findings/{id} [put]
// @Tags        Finding
func UpdateFinding(c *gin.Context) {
	log.Info().Msg("UpdateFinding initiated")

	var body FindingRequest
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Err(err).Msg("Error binding JSON in UpdateFinding")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})
		return
	}

	id := c.Param("id")

	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching finding in UpdateFinding")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding not found",
		})
		return
	}

	if body.ProjectID != 0 {
		finding.ProjectID = body.ProjectID
	}
	if body.Title != "" {
		finding.Title = body.Title
	}
	if body.Description != "" {
		finding.Description = body.Description
	}
	if body.Severity != 0 {
		finding.Severity = body.Severity
	}
	if body.CWE != 0 {
		finding.CWE = body.CWE
	}
	if body.Line != 0 {
		finding.Line = body.Line
	}
	if body.FilePath != "" {
		finding.FilePath = body.FilePath
	}
	if body.VulnIDFromTool != "" {
		finding.VulnIDFromTool = body.VulnIDFromTool
	}
	if body.Mitigation != "" {
		finding.Mitigation = body.Mitigation
	}
	if body.Reference != "" {
		finding.Reference = body.Reference
	}
	if body.Active != finding.Active {
		finding.Active = body.Active
	}
	if body.DynamicFinding != finding.DynamicFinding {
		finding.DynamicFinding = body.DynamicFinding
	}
	if body.Duplicate != finding.Duplicate {
		finding.Duplicate = body.Duplicate
	}
	if body.RiskAccepted != finding.RiskAccepted {
		finding.RiskAccepted = body.RiskAccepted
	}
	if body.StaticFinding != finding.StaticFinding {
		finding.StaticFinding = body.StaticFinding
	}

	err = persistence.FindingRepo.Update(finding)
	if err != nil {
		log.Error().Err(err).Msg("Error updating finding in UpdateFinding")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding not found",
		})
		return
	}

	log.Info().Msg("Finding updated successfully in UpdateFinding")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// DeleteFinding godoc
// @Summary     Delete finding by ID
// @Description Delete finding by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "ID"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/findings/{id} [delete]
// @Tags        Finding
func DeleteFinding(c *gin.Context) {
	log.Info().Msg("DeleteFinding initiated")

	id := c.Param("id")

	err := finding_services.DeleteFinding(id)
	if err != nil {
		log.Error().Err(err).Msg("Error deleting finding in DeleteFinding")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: err.Error(),
		})
		return
	}

	log.Info().Msg("Finding deleted successfully in DeleteFinding")
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// / ToggleFindingStatus godoc
// @Summary     Toggle finding status by ID (close or open)
// @Description Toggle finding status by ID (close or open)
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "ID" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/findings/toggle-status/{id} [put]
// @Tags        Finding
func ToggleFindingStatus(c *gin.Context) {
	log.Info().Msg("ToggleFindingStatus initiated")

	id := c.Param("id")
	findingID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		log.Error().Err(err).Msg("Invalid finding ID")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid finding ID",
		})
		return
	}

	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching finding in ToggleFindingStatus")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding not found",
		})
		return
	}

	finding.Active = !finding.Active
	err = persistence.FindingRepo.Update(finding)
	if err != nil {
		log.Error().Err(err).Msg("Error updating finding in ToggleFindingStatus")
		c.JSON(http.StatusInternalServerError, http_res.HTTPResponse{
			Code:    http.StatusInternalServerError,
			Message: "Error updating finding",
		})
		return
	}

	status := "closed"
	if finding.Active {
		status = "opened"
	}

	log.Info().Msgf("Finding %s successfully for ID: %d", status, findingID)
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}

// ToggleRiskAcceptanceFinding godoc
// @Summary     Toggle risk acceptance for finding by ID
// @Description Toggle risk acceptance for finding by ID
// @Accept      json
// @Produce     json
// @Param       id  path     integer true "ID" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/findings/risk-accept/{id} [put]
// @Tags        Finding
func ToggleRiskAcceptanceFinding(c *gin.Context) {
	log.Info().Msg("ToggleRiskAcceptanceFinding initiated")

	id := c.Param("id")
	findingID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		log.Error().Err(err).Msg("Invalid finding ID")
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid finding ID",
		})
		return
	}

	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Err(err).Msg("Error fetching finding in ToggleRiskAcceptanceFinding")
		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding not found",
		})
		return
	}

	finding.RiskAccepted = !finding.RiskAccepted
	err = persistence.FindingRepo.Update(finding)
	if err != nil {
		log.Error().Err(err).Msg("Error updating finding in ToggleRiskAcceptanceFinding")
		c.JSON(http.StatusInternalServerError, http_res.HTTPResponse{
			Code:    http.StatusInternalServerError,
			Message: "Error updating finding",
		})
		return
	}

	status := "accepted"
	if !finding.RiskAccepted {
		status = "unaccepted"
	}

	log.Info().Msgf("Risk %s successfully for finding ID: %d", status, findingID)
	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
