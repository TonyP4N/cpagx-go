package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetupRoutes 设置API路由
func SetupRoutes(r *gin.Engine, handler *Handler, proxy *VersionProxy) {
	// 设置文件上传大小限制 (300MB)
	r.MaxMultipartMemory = 300 << 20 // 300MB
	// 版本管理路由
	versionAPI := r.Group("/api/version")
	{
		versionAPI.GET("/list", proxy.GetVersions())            // 获取所有版本
		versionAPI.POST("/switch", proxy.SwitchVersion())       // 切换版本
		versionAPI.GET("/health/:version", proxy.HealthCheck()) // 版本健康检查
	}

	// 任务管理路由
	tasksAPI := r.Group("/api/tasks")
	{
		tasksAPI.GET("/list", proxy.GetTaskList())                         // 获取任务列表
		tasksAPI.GET("/download/:task_id/:filename", proxy.DownloadFile()) // 下载文件
		tasksAPI.GET("/status/batch", proxy.GetBatchTaskStatus())          // 批量获取任务状态
		tasksAPI.GET("/queue/status", proxy.GetQueueStatus())              // 获取队列状态
	}

	// 版本路由 - v1
	v1API := r.Group("/api/v1")
	{
		v1API.Any("/*path", proxy.ProxyToVersion("v1"))
	}

	// 版本路由 - v2
	v2API := r.Group("/api/v2")
	{
		v2API.Any("/*path", proxy.ProxyToVersion("v2"))
	}

	// 默认API路由（兼容性）
	api := r.Group("/api")
	{
		// CPAG生成相关路由
		cpag := api.Group("/cpag")
		{
			cpag.POST("/generate", handler.GenerateCPAG)   // 生成CPAG
			cpag.GET("/status/:id", handler.GetCPAGStatus) // 获取生成状态
			cpag.GET("/result/:id", handler.GetCPAGResult) // 获取生成结果
		}

		// 图数据可视化相关路由
		graph := api.Group("/graph")
		{
			graph.GET("/tasks", handler.GetGraphTasks)               // 获取图任务列表
			graph.GET("/data/:task_id", handler.GetGraphData)        // 获取图数据
			graph.DELETE("/tasks/:task_id", handler.DeleteGraphTask) // 删除图任务
			graph.GET("/health", handler.GetNeo4jHealth)             // Neo4j健康检查
			graph.GET("/browser", handler.GetNeo4jBrowserURL)        // 获取Neo4j Browser访问URL
		}

		// 健康检查
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"status":  "healthy",
				"service": "cpagx-go",
				"version": "1.0.0",
			})
		})
	}

	// 兼容性路由
	r.GET("/api/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	// 初始页面
	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, "<h1>CPAGX API</h1><p>Server is running.</p>")
	})
}
