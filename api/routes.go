package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetupRoutes 设置API路由
func SetupRoutes(r *gin.Engine, handler *Handler) {
	// API版本组
	api := r.Group("/api/v1")

	// CPAG生成相关路由
	cpag := api.Group("/cpag")
	{
		cpag.POST("/generate", handler.GenerateCPAG)   // 生成CPAG
		cpag.GET("/status/:id", handler.GetCPAGStatus) // 获取生成状态
		cpag.GET("/result/:id", handler.GetCPAGResult) // 获取生成结果
		cpag.POST("/analyze", handler.AnalyzeCPAG)     // 分析CPAG
	}

	// 健康检查
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "cpagx-go",
			"version": "1.0.0",
		})
	})

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
