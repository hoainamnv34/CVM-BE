package controllers

import (
	"net/http"
	"strconv"
	finding_service "vulnerability-management/internal/api/services/finding"
	models "vulnerability-management/internal/pkg/models/findings"
	http_res "vulnerability-management/pkg/http-res"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type responseBody struct {
	OpenCount  int `json:"open_count" form:"open_count"`
	CloseCount int `json:"close_count" form:"close_count"`
	RiskCount  int `json:"risk_count" form:"risk_count"`
}

// GetFindingsByProjectID godoc
// @Summary     Get Findings By Project Dashboard
// @Description Get finding type count by Project ID
// @Produce     json
// @Param       id  path     integer true "id" min(1)
// @Success     200 {object} http_res.HTTPResponse
// @Router      /api/dashboard/finding-type-count/{id} [get]
// @Tags        Dashboard
func GetFindingsByProjectID(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)

	openedCount, err := finding_service.CountFindings(models.Finding{
		ProjectID: id,
		Active:    true,
	})

	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding is not found",
		})

		return
	}

	closedCount, err := finding_service.CountFindings(models.Finding{
		ProjectID: id,
		Active:    false,
	})

	if err != nil {
		log.Error().Msgf(err.Error())

		c.JSON(http.StatusNotFound, http_res.HTTPResponse{
			Code:    http.StatusNotFound,
			Message: "Finding is not found",
		})

		return
	}

	riskAcceptedCount, err := finding_service.CountFindings(models.Finding{
		ProjectID:    id,
		RiskAccepted: true,
	})

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
		Data: responseBody{
			OpenCount:  openedCount,
			CloseCount: closedCount,
			RiskCount:  riskAcceptedCount,
		},
	})
}
