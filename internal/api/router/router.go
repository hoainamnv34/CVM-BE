package router

import (
	"fmt"
	"io"
	"os"

	"github.com/gin-gonic/gin"

	controllers "vulnerability-management/internal/api/controllers"
	middlewares "vulnerability-management/internal/api/middlewares"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func Setup() *gin.Engine {
	app := gin.New()

	// Logging to a file.
	f, _ := os.Create("log/api.log")
	gin.DisableConsoleColor()
	gin.DefaultWriter = io.MultiWriter(f)

	// Middlewares
	app.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - - [%s] \"%s %s %s %d %s \" \" %s\" \" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format("02/Jan/2006:15:04:05 -0700"),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))
	app.Use(gin.Recovery())
	app.Use(middlewares.CORS())
	app.NoRoute(middlewares.NoRouteHandler())

	// Routes

	// ================== Docs Routes
	app.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// ================== Project groups routes
	app.POST("/api/project-groups", controllers.CreateProjectGroup)
	app.GET("/api/project-groups/:id", controllers.GetProjectGroupByID)
	app.GET("/api/project-groups", controllers.GetProjectGroups)
	app.PUT("/api/project-groups/:id", controllers.UpdateProjectGroup)
	app.DELETE("/api/project-groups/:id", controllers.DeleteProjectGroup)

	// ================== Projects routes
	app.POST("/api/projects", controllers.CreateProject)
	app.GET("/api/projects/:id", controllers.GetProjectByID)
	app.GET("/api/projects", controllers.GetProjects)
	app.PUT("/api/projects/:id", controllers.UpdateProject)
	app.DELETE("/api/projects/:id", controllers.DeleteProject)

	// ==================  Pipelines Evaluation routes
	app.POST("/api/pipeline-evaluations", controllers.CreatePipelineEvaluation)
	app.GET("/api/pipeline-evaluations/count", controllers.CountPipelineEvaluations)
	app.GET("/api/pipeline-evaluations/:id", controllers.GetPipelineEvaluationByID)
	app.GET("/api/pipeline-evaluations", controllers.GetPipelineEvaluations)
	app.PUT("/api/pipeline-evaluations/:id", controllers.UpdatePipelineEvaluation)
	app.DELETE("/api/pipeline-evaluations/:id", controllers.DeletePipelineEvaluation)

	// ================== Pipeline runs routes
	app.POST("/api/pipeline-runs", controllers.CreatePipelineRun)
	app.GET("/api/pipeline-runs/evaluate", controllers.EvaluatePipelineRun)
	app.GET("/api/pipeline-runs/:id", controllers.GetPipelineRunByID)
	app.GET("/api/pipeline-runs", controllers.GetPipelineRuns)
	app.PUT("/api/pipeline-runs/:id", controllers.UpdatePipelineRun)
	app.DELETE("/api/pipeline-runs/:id", controllers.DeletePipelineRun)
	app.GET("/api/pipeline-runs/test-list/:id", controllers.GetTestList)

	// ================== Tests routes
	app.POST("/api/tests", controllers.CreateTest)
	app.GET("/api/tests/:id", controllers.GetTestByID)
	app.GET("/api/tests", controllers.GetTests)
	app.PUT("/api/tests/:id", controllers.UpdateTest)
	app.DELETE("/api/tests/:id", controllers.DeleteTest)
	app.GET("/api/tests/projects/:project_id", controllers.GetTestsByProjectID)


	
	// ================== Tool types routes
	app.POST("/api/tool-types", controllers.CreateToolType)
	app.GET("/api/tool-types/:id", controllers.GetToolTypeByID)
	app.GET("/api/tool-types", controllers.GetToolTypes)
	app.PUT("/api/tool-types/:id", controllers.UpdateToolType)
	app.DELETE("/api/tool-types/:id", controllers.DeleteToolType)

	// ================== Findings routes
	app.POST("/api/findings", controllers.CreateFinding)
	// app.GET("/api/findings/parent-all", controllers.GetAllFindingsByParent)
	app.GET("/api/findings/parent/count", controllers.CountFindingsByParent)
	app.GET("/api/findings/parent", controllers.GetFindingsByParent)
	app.GET("/api/findings/count", controllers.CountFindings)
	app.GET("/api/findings/:id", controllers.GetFindingByID)
	app.GET("/api/findings", controllers.GetFindings)
	app.PUT("/api/findings/:id", controllers.UpdateFinding)
	app.DELETE("/api/findings/:id", controllers.DeleteFinding)
	app.PUT("/api/findings/risk-accept/:id", controllers.ToggleRiskAcceptanceFinding)
	app.PUT("/api/findings/toggle-status/:id", controllers.ToggleFindingStatus)

	// ================== Import Test routes
	app.POST("/api/import", controllers.ImportTestResult)

	// ================== Dashboard
	app.GET("/api/dashboard/finding-type-count/:id", controllers.GetFindingsByProjectID)

	return app
}
