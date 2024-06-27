package controllers

import (
	"net/http"

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
// @Param       id  path     integer true "id" min(1)
// @Success     200         {object} http_res.HTTPResponse
// @Router      /api/findings/{id} [get]
// @Security    Authorization Token
// @Tags        Finding
func GetFindingByID(c *gin.Context) {
	id := c.Param("id")

	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding is not found",
		})

		return
	}

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
// @Param       project_id          query    integer false "project_id"
// @Param       title               query    string  false "title"
// @Param       risk_description    query    string  false "risk_description"
// @Param       severity            query    integer false "severity"
// @Param       cwe                 query    integer false "cwe"
// @Param       line                query    integer false "line"
// @Param       file_path           query    string  false "file_path"
// @Param       vuln_id_from_tool   query    string  false "vuln_id_from_tool"
// @Param       unique_id_from_tool query    string  false "unique_id_from_tool"
// @Param       mitigation          query    string  false "mitigation"
// @Param       impact              query    string  false "impact"
// @Param       reference           query    string  false "reference"
// @Param       active              query    bool    false "active"
// @Param       dynamic_finding     query    bool    false "dynamic_finding"
// @Param       duplicate           query    bool    false "duplicate"
// @Param       risk_accepted       query    bool    false "risk_accepted"
// @Param       static_finding      query    bool    false "static_finding"
// @Param       page        query    integer false "page"
// @Param       size        query    integer false "size"
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/findings [get]
// @Security    Authorization Token
// @Tags        Finding
func GetFindings(c *gin.Context) {
	query := models.Finding{}

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

	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}

	if query.Title != "" {
		where["title"] = query.Title
	}

	if query.RiskDescription != "" {
		where["risk_description"] = query.RiskDescription
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

	if query.UniqueIDFromTool != "" {
		where["unique_id_from_tool"] = query.UniqueIDFromTool
	}

	if query.Mitigation != "" {
		where["mitigation"] = query.Mitigation
	}

	if query.Impact != "" {
		where["impact"] = query.Impact
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

	findings, count, err := persistence.FindingRepo.Query(where, offset, limit)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Findings not found",
		})

		return
	}

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
// @Param       parent_id   query    integer false "parent_id"
// @Param       parent_type query    integer false "parent_type"
// @Param       page                query    integer false "page"
// @Param       size                query    integer false "size"
// @Success     200         {object} http_res.HTTPResponse
// @Router      /api/findings/parent [get]
// @Security    Authorization Token
// @Tags        Finding
func GetFindingsByParent(c *gin.Context) {
	query := struct {
		ParentID   uint64 `json:"parent_id" form:"parent_id"`
		ParentType uint64 `json:"parent_type" form:"parent_type"`
	}{}

	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})

		return
	}

	findings := &[]models.Finding{}
	count := 0

	offset, limit := helpers.GetPagination(c.Query("page"), c.Query("size"))

	if query.ParentType == 1 {
		projectGroup, err := persistence.ProjectGroupRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Project group is not found",
			})

			return
		}

		findings, count, err = persistence.FindingRepo.QueryByProjectGroupID(projectGroup.ID, offset, limit)
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Findings not found",
			})

			return
		}
	} else if query.ParentType == 2 {
		project, err := persistence.ProjectRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Project is not found",
			})

			return
		}

		findings, count, err = persistence.FindingRepo.QueryByProjectID(project.ID, offset, limit)
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Findings not found",
			})

			return
		}
	} else if query.ParentType == 3 {
		pipelineRun, err := persistence.PipelineRunRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Pipeline run is not found",
			})

			return
		}

		findings, count, err = persistence.FindingRepo.QueryByPipelineRunID(pipelineRun.ID, offset, limit)
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Findings not found",
			})

			return
		}
	} else if query.ParentType == 4 {
		test, err := persistence.TestRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Test is not found",
			})

			return
		}

		findings, count, err = persistence.FindingRepo.QueryByTestID(test.ID, offset, limit)
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Findings not found",
			})

			return
		}
	} else {
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:      http.StatusOK,
		Message:   "Success",
		Data:      findings,
		DataCount: count,
	})
}

// // GetAllFindingsByParent godoc
// // @Summary     Get all findings by query parent
// // @Description Get all findings by query parent
// // @Produce     json
// // @Param       parent_id   query    integer false "parent_id"
// // @Param       parent_type query    integer false "parent_type"
// // @Success     200         {object} http_res.HTTPResponse
// // @Router      /api/findings/parent-all [get]
// // @Security    Authorization Token
// // @Tags        Finding
// func GetAllFindingsByParent(c *gin.Context) {
// 	query := struct {
// 		ParentID   uint64 `json:"parent_id" form:"parent_id"`
// 		ParentType uint64 `json:"parent_type" form:"parent_type"`
// 	}{}

// 	err := c.ShouldBindQuery(&query)
// 	if err != nil {
// 		log.Error().Msgf(err.Error())

// 		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
// 			Code:    http.StatusBadRequest,
// 			Message: "Invalid query parameters",
// 		})

// 		return
// 	}

// 	type Test struct {
// 		tests_model.Test
// 		Findings []models.Finding `json:"findings" form:"findings"`
// 	}

// 	type PipelineRun struct {
// 		pipeline_runs_model.PipelineRun
// 		Tests []Test `json:"tests" form:"tests"`
// 	}

// 	type CICDPipeline struct {
// 		cicd_pipelines_model.CICDPipeline
// 		PipelineRuns []PipelineRun `json:"pipeline_runs" form:"pipeline_runs"`
// 	}

// 	type Project struct {
// 		projects_model.Project
// 		CICDPipelines []CICDPipeline `json:"cicd_pipelines" form:"cicd_pipelines"`
// 	}

// 	type ProjectGroup struct {
// 		project_groups_model.ProjectGroup
// 		Projects []Project `json:"projects" form:"projects"`
// 	}

// 	if query.ParentType == 1 {
// 		projectGroup, err := persistence.ProjectGroupRepo.Get(strconv.Itoa(int(query.ParentID)))
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "Project group not found",
// 			})

// 			return
// 		}

// 		res := ProjectGroup{
// 			ProjectGroup: *projectGroup,
// 		}

// 		projects, _, err := persistence.ProjectRepo.Query(map[string]interface{}{
// 			"project_group_id": projectGroup.ID,
// 		}, 0, math.MaxInt)
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "Projects not found",
// 			})

// 			return
// 		}

// 		for _, project := range *projects {
// 			projectItem := Project{
// 				Project: project,
// 			}

// 			cicdPipelines, _, err := persistence.CICDPipelineRepo.Query(map[string]interface{}{
// 				"project_id": project.ID,
// 			}, 0, math.MaxInt)
// 			if err != nil {
// 				log.Error().Msgf(err.Error())

// 				c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 					Code:    http.StatusNotFound,
// 					Message: "CICD pipelines not found",
// 				})

// 				return
// 			}

// 			for _, cicdPipeline := range *cicdPipelines {
// 				cicdPipelineItem := CICDPipeline{
// 					CICDPipeline: cicdPipeline,
// 				}

// 				pipelineRuns, _, err := persistence.PipelineRunRepo.Query(map[string]interface{}{
// 					"cicd_pipeline_id": cicdPipeline.ID,
// 				}, 0, math.MaxInt)
// 				if err != nil {
// 					log.Error().Msgf(err.Error())

// 					c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 						Code:    http.StatusNotFound,
// 						Message: "Pipeline runs not found",
// 					})
// 					return
// 				}

// 				for _, pipelineRun := range *pipelineRuns {
// 					pipelineRunItem := PipelineRun{
// 						PipelineRun: pipelineRun,
// 					}

// 					tests, _, err := persistence.TestRepo.Query(map[string]interface{}{
// 						"pipeline_run_id": pipelineRun.ID,
// 					}, 0, math.MaxInt)
// 					if err != nil {
// 						log.Error().Msgf(err.Error())

// 						c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 							Code:    http.StatusNotFound,
// 							Message: "Tests not found",
// 						})
// 						return
// 					}

// 					for _, test := range *tests {
// 						testItem := Test{
// 							Test: test,
// 						}

// 						findings, _, err := persistence.FindingRepo.Query(map[string]interface{}{
// 							"test_id": test.ID,
// 						}, 0, math.MaxInt)
// 						if err != nil {
// 							log.Error().Msgf(err.Error())

// 							c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 								Code:    http.StatusNotFound,
// 								Message: "Findings not found",
// 							})
// 							return
// 						}

// 						testItem.Findings = append(testItem.Findings, *findings...)
// 						pipelineRunItem.Tests = append(pipelineRunItem.Tests, testItem)
// 					}

// 					cicdPipelineItem.PipelineRuns = append(cicdPipelineItem.PipelineRuns, pipelineRunItem)
// 				}

// 				projectItem.CICDPipelines = append(projectItem.CICDPipelines, cicdPipelineItem)
// 			}

// 			res.Projects = append(res.Projects, projectItem)
// 		}

// 		c.JSON(http.StatusOK, http_res.HTTPResponse{
// 			Code:    http.StatusOK,
// 			Message: "Success",
// 			Data:    res,
// 		})
// 	} else if query.ParentType == 2 {
// 		project, err := persistence.ProjectRepo.Get(strconv.Itoa(int(query.ParentID)))
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "Project not found",
// 			})

// 			return
// 		}

// 		res := Project{
// 			Project: *project,
// 		}

// 		cicdPipelines, _, err := persistence.CICDPipelineRepo.Query(map[string]interface{}{
// 			"project_id": project.ID,
// 		}, 0, math.MaxInt)
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "CICD pipelines not found",
// 			})

// 			return
// 		}

// 		for _, cicdPipeline := range *cicdPipelines {
// 			cicdPipelineItem := CICDPipeline{
// 				CICDPipeline: cicdPipeline,
// 			}

// 			pipelineRuns, _, err := persistence.PipelineRunRepo.Query(map[string]interface{}{
// 				"cicd_pipeline_id": cicdPipeline.ID,
// 			}, 0, math.MaxInt)
// 			if err != nil {
// 				log.Error().Msgf(err.Error())

// 				c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 					Code:    http.StatusNotFound,
// 					Message: "Pipeline runs not found",
// 				})
// 				return
// 			}

// 			for _, pipelineRun := range *pipelineRuns {
// 				pipelineRunItem := PipelineRun{
// 					PipelineRun: pipelineRun,
// 				}

// 				tests, _, err := persistence.TestRepo.Query(map[string]interface{}{
// 					"pipeline_run_id": pipelineRun.ID,
// 				}, 0, math.MaxInt)
// 				if err != nil {
// 					log.Error().Msgf(err.Error())

// 					c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 						Code:    http.StatusNotFound,
// 						Message: "Tests not found",
// 					})
// 					return
// 				}

// 				for _, test := range *tests {
// 					testItem := Test{
// 						Test: test,
// 					}

// 					findings, _, err := persistence.FindingRepo.Query(map[string]interface{}{
// 						"test_id": test.ID,
// 					}, 0, math.MaxInt)
// 					if err != nil {
// 						log.Error().Msgf(err.Error())

// 						c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 							Code:    http.StatusNotFound,
// 							Message: "Findings not found",
// 						})
// 						return
// 					}

// 					testItem.Findings = append(testItem.Findings, *findings...)
// 					pipelineRunItem.Tests = append(pipelineRunItem.Tests, testItem)
// 				}

// 				cicdPipelineItem.PipelineRuns = append(cicdPipelineItem.PipelineRuns, pipelineRunItem)
// 			}

// 			res.CICDPipelines = append(res.CICDPipelines, cicdPipelineItem)
// 		}

// 		c.JSON(http.StatusOK, http_res.HTTPResponse{
// 			Code:    http.StatusOK,
// 			Message: "Success",
// 			Data:    res,
// 		})
// 	} else if query.ParentType == 3 {
// 		cicdPipeline, err := persistence.CICDPipelineRepo.Get(strconv.Itoa(int(query.ParentID)))
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "CICD pipeline not found",
// 			})

// 			return
// 		}

// 		res := CICDPipeline{
// 			CICDPipeline: *cicdPipeline,
// 		}

// 		pipelineRuns, _, err := persistence.PipelineRunRepo.Query(map[string]interface{}{
// 			"cicd_pipeline_id": cicdPipeline.ID,
// 		}, 0, math.MaxInt)
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "Pipeline runs not found",
// 			})

// 			return
// 		}

// 		for _, pipelineRun := range *pipelineRuns {
// 			pipelineRunItem := PipelineRun{
// 				PipelineRun: pipelineRun,
// 			}

// 			tests, _, err := persistence.TestRepo.Query(map[string]interface{}{
// 				"pipeline_run_id": pipelineRun.ID,
// 			}, 0, math.MaxInt)
// 			if err != nil {
// 				log.Error().Msgf(err.Error())

// 				c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 					Code:    http.StatusNotFound,
// 					Message: "Tests not found",
// 				})
// 				return
// 			}

// 			for _, test := range *tests {
// 				testItem := Test{
// 					Test: test,
// 				}

// 				findings, _, err := persistence.FindingRepo.Query(map[string]interface{}{
// 					"test_id": test.ID,
// 				}, 0, math.MaxInt)
// 				if err != nil {
// 					log.Error().Msgf(err.Error())

// 					c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 						Code:    http.StatusNotFound,
// 						Message: "Findings not found",
// 					})
// 					return
// 				}

// 				testItem.Findings = append(testItem.Findings, *findings...)
// 				pipelineRunItem.Tests = append(pipelineRunItem.Tests, testItem)
// 			}

// 			res.PipelineRuns = append(res.PipelineRuns, pipelineRunItem)
// 		}

// 		c.JSON(http.StatusOK, http_res.HTTPResponse{
// 			Code:    http.StatusOK,
// 			Message: "Success",
// 			Data:    res,
// 		})
// 	} else if query.ParentType == 4 {
// 		pipelineRun, err := persistence.PipelineRunRepo.Get(strconv.Itoa(int(query.ParentID)))
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "Pipeline run not found",
// 			})

// 			return
// 		}

// 		res := PipelineRun{
// 			PipelineRun: *pipelineRun,
// 		}

// 		tests, _, err := persistence.TestRepo.Query(map[string]interface{}{
// 			"pipeline_run_id": pipelineRun.ID,
// 		}, 0, math.MaxInt)
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "Tests not found",
// 			})
// 			return
// 		}

// 		for _, test := range *tests {
// 			testItem := Test{
// 				Test: test,
// 			}

// 			findings, _, err := persistence.FindingRepo.Query(map[string]interface{}{
// 				"test_id": test.ID,
// 			}, 0, math.MaxInt)
// 			if err != nil {
// 				log.Error().Msgf(err.Error())

// 				c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 					Code:    http.StatusNotFound,
// 					Message: "Findings not found",
// 				})
// 				return
// 			}

// 			testItem.Findings = append(testItem.Findings, *findings...)
// 			res.Tests = append(res.Tests, testItem)
// 		}

// 		c.JSON(http.StatusOK, http_res.HTTPResponse{
// 			Code:    http.StatusOK,
// 			Message: "Success",
// 			Data:    res,
// 		})
// 	} else if query.ParentType == 5 {
// 		test, err := persistence.TestRepo.Get(strconv.Itoa(int(query.ParentID)))
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "Test not found",
// 			})

// 			return
// 		}

// 		res := Test{
// 			Test: *test,
// 		}

// 		findings, _, err := persistence.FindingRepo.Query(map[string]interface{}{
// 			"test_id": test.ID,
// 		}, 0, math.MaxInt)
// 		if err != nil {
// 			log.Error().Msgf(err.Error())

// 			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
// 				Code:    http.StatusNotFound,
// 				Message: "Findings not found",
// 			})
// 			return
// 		}

// 		res.Findings = append(res.Findings, *findings...)

// 		c.JSON(http.StatusOK, http_res.HTTPResponse{
// 			Code:    http.StatusOK,
// 			Message: "Success",
// 			Data:    res,
// 		})
// 	} else {
// 		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
// 			Code:    http.StatusBadRequest,
// 			Message: "Invalid query parameters",
// 		})

// 		return
// 	}
// }

// CountFindingsByParent godoc
// @Summary     Count findings by query parent
// @Description Count findings by query parent
// @Produce     json
// @Param       parent_id   query    integer false "parent_id"
// @Param       parent_type query    integer false "parent_type"
// @Success     200                 {object} http_res.HTTPResponse
// @Router      /api/findings/parent/count [get]
// @Security    Authorization Token
// @Tags        Finding
func CountFindingsByParent(c *gin.Context) {
	query := struct {
		ParentID   uint64 `json:"parent_id" form:"parent_id"`
		ParentType uint64 `json:"parent_type" form:"parent_type"`
	}{}

	err := c.ShouldBindQuery(&query)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})

		return
	}

	count := 0

	if query.ParentType == 1 {
		projectGroup, err := persistence.ProjectGroupRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Project group is not found",
			})

			return
		}

		count, err = persistence.FindingRepo.CountByProjectGroupID(projectGroup.ID)
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Findings not found",
			})

			return
		}
	} else if query.ParentType == 2 {
		project, err := persistence.ProjectRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Project is not found",
			})

			return
		}

		count, err = persistence.FindingRepo.CountByProjectID(project.ID)
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Findings not found",
			})

			return
		}
	} else if query.ParentType == 3 {
		pipelineRun, err := persistence.PipelineRunRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Pipeline run is not found",
			})

			return
		}

		count, err = persistence.FindingRepo.CountByPipelineRunID(pipelineRun.ID)
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Findings not found",
			})

			return
		}
	} else if query.ParentType == 4 {
		test, err := persistence.TestRepo.Get(c.Query("parent_id"))
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Test is not found",
			})

			return
		}

		count, err = persistence.FindingRepo.CountByTestID(test.ID)
		if err != nil {
			log.Error().Msgf(err.Error())

			c.JSON(http.StatusNotFound, http_res.HTTPResponse{
				Code:    http.StatusNotFound,
				Message: "Findings not found",
			})

			return
		}
	} else {
		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid query parameters",
		})

		return
	}

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
// @Param       project_id          query    integer false "project_id"
// @Param       title               query    string  false "title"
// @Param       risk_description    query    string  false "risk_description"
// @Param       severity            query    integer false "severity"
// @Param       cwe                 query    integer false "cwe"
// @Param       line                query    integer false "line"
// @Param       file_path           query    string  false "file_path"
// @Param       vuln_id_from_tool   query    string  false "vuln_id_from_tool"
// @Param       unique_id_from_tool query    string  false "unique_id_from_tool"
// @Param       mitigation          query    string  false "mitigation"
// @Param       impact              query    string  false "impact"
// @Param       reference           query    string  false "reference"
// @Param       reviewer            query    integer false "reviewer"
// @Param       active              query    bool    false "active"
// @Param       dynamic_finding     query    bool    false "dynamic_finding"
// @Param       duplicate           query    bool    false "duplicate"
// @Param       risk_accepted       query    bool    false "risk_accepted"
// @Param       static_finding      query    bool    false "static_finding"
// @Success     200                 {object} http_res.HTTPResponse
// @Router      /api/findings/count [get]
// @Security    Authorization Token
// @Tags        Finding
func CountFindings(c *gin.Context) {
	query := models.Finding{}

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

	if query.ProjectID != 0 {
		where["project_id"] = query.ProjectID
	}

	if query.Title != "" {
		where["title"] = query.Title
	}

	if query.RiskDescription != "" {
		where["risk_description"] = query.RiskDescription
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

	if query.UniqueIDFromTool != "" {
		where["unique_id_from_tool"] = query.UniqueIDFromTool
	}

	if query.Mitigation != "" {
		where["mitigation"] = query.Mitigation
	}

	if query.Impact != "" {
		where["impact"] = query.Impact
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
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Findings not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
		Data:    count,
	})
}

// CreateFinding godoc
// @Summary     Create finding
// @Description Create finding
// @Accept      json
// @Produce     json
// @Param       body body     models.Finding true "body"
// @Success     201  {object} http_res.HTTPResponse
// @Router      /api/findings [post]
// @Tags        Finding
func CreateFinding(c *gin.Context) {
	body := models.Finding{}
	err := c.BindJSON(&body)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusBadRequest, http_res.HTTPResponse{
			Code:    http.StatusBadRequest,
			Message: "Invalid body parameters",
		})

		return
	}

	finding := models.Finding{
		ProjectID:        body.ProjectID,
		Title:            body.Title,
		RiskDescription:  body.RiskDescription,
		Severity:         body.Severity,
		CWE:              body.CWE,
		Line:             body.Line,
		FilePath:         body.FilePath,
		VulnIDFromTool:   body.VulnIDFromTool,
		UniqueIDFromTool: body.UniqueIDFromTool,
		Mitigation:       body.Mitigation,
		Impact:           body.Impact,
		Reference:        body.Reference,
		Active:           body.Active,
		DynamicFinding:   body.DynamicFinding,
		Duplicate:        body.Duplicate,
		RiskAccepted:     body.RiskAccepted,
		StaticFinding:    body.StaticFinding,
	}

	res, err := persistence.FindingRepo.Add(&finding)
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

// UpdateFinding godoc
// @Summary     Update finding by ID
// @Description Update finding by ID
// @Accept      json
// @Produce     json
// @Param       id   path     integer        true "id" min(1)
// @Param       body body     models.Finding true "body"
// @Success     200  {object} http_res.HTTPResponse
// @Router      /api/findings/{id} [put]
// @Tags        Finding
func UpdateFinding(c *gin.Context) {
	body := models.Finding{}
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

	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding is not found",
		})

		return
	}

	if body.ProjectID != 0 {
		finding.ProjectID = body.ProjectID
	}

	if body.Title != "" {
		finding.Title = body.Title
	}

	if body.RiskDescription != "" {
		finding.RiskDescription = body.RiskDescription
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

	if body.UniqueIDFromTool != "" {
		finding.UniqueIDFromTool = body.UniqueIDFromTool
	}

	if body.Mitigation != "" {
		finding.Mitigation = body.Mitigation
	}

	if body.Impact != "" {
		finding.Impact = body.Impact
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
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding is not found",
		})

		return
	}

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
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/findings/{id} [delete]
// @Tags        Finding
func DeleteFinding(c *gin.Context) {
	id := c.Param("id")

	finding, err := persistence.FindingRepo.Get(id)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding is not found",
		})

		return
	}

	err = persistence.FindingRepo.Delete(finding)
	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding is not found",
		})

		return
	}

	c.JSON(http.StatusOK, http_res.HTTPResponse{
		Code:    http.StatusOK,
		Message: "Success",
	})
}
