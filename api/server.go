package api

import (
	"log"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// NewServer 创建新的Gin服务器
func NewServer() *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// CORS 配置
	corsConfig := cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:    []string{"Origin", "Content-Type", "Accept", "Authorization"},
		MaxAge:          12 * time.Hour,
	}
	r.Use(cors.New(corsConfig))

	// 获取Python服务URL（从环境变量）
	pythonServiceURL := os.Getenv("PYTHON_SERVICE_URL")
	if pythonServiceURL == "" {
		pythonServiceURL = "http://localhost:8000" // 默认值
	}

	// 创建处理器
	handler := NewHandler(pythonServiceURL)

	// 设置路由
	SetupRoutes(r, handler)

	log.Printf("API server initialized with Python service at: %s", pythonServiceURL)
	return r
}
