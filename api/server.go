package api

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

// NewServer 创建新的Fiber服务器
func NewServer() *fiber.App {
	app := fiber.New(fiber.Config{
		AppName: "CPAGX-Go API",
	})

	// 中间件
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization",
	}))

	// 获取Python服务URL（从环境变量）
	pythonServiceURL := os.Getenv("PYTHON_SERVICE_URL")
	if pythonServiceURL == "" {
		pythonServiceURL = "http://localhost:8000" // 默认值
	}

	// 创建处理器
	handler := NewHandler(pythonServiceURL)

	// 设置路由
	SetupRoutes(app, handler)

	log.Printf("API server initialized with Python service at: %s", pythonServiceURL)
	return app
}
