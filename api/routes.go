package api

import (
	"github.com/gofiber/fiber/v2"
)

// SetupRoutes 设置API路由
func SetupRoutes(app *fiber.App, handler *Handler) {
	// API版本组
	api := app.Group("/api/v1")

	// CPAG生成相关路由
	cpag := api.Group("/cpag")
	cpag.Post("/generate", handler.GenerateCPAG)   // 生成CPAG
	cpag.Get("/status/:id", handler.GetCPAGStatus) // 获取生成状态
	cpag.Get("/result/:id", handler.GetCPAGResult) // 获取生成结果
	cpag.Post("/analyze", handler.AnalyzeCPAG)     // 分析CPAG

	// 健康检查
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"service": "cpagx-go",
			"version": "1.0.0",
		})
	})

	// 兼容性路由
	app.Get("/api/ping", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "pong"})
	})
}
