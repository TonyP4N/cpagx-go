package api

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/config"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// NewServer 创建新的Gin服务器
func NewServer(cfg *config.Config) *gin.Engine {
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

	// 加载版本配置
	versionsConfig := loadVersionsConfig()

	// 创建版本代理
	proxy := NewVersionProxy(versionsConfig)

	// 使用配置中的服务URL，或从环境变量获取（兼容性）
	pythonServiceURL := cfg.Python.ServiceURL
	if envURL := os.Getenv("PYTHON_SERVICE_URL"); envURL != "" {
		pythonServiceURL = envURL
	}

	// 获取RabbitMQ URL
	rabbitMQURL := os.Getenv("RABBITMQ_URL")
	if rabbitMQURL == "" {
		rabbitMQURL = "amqp://guest:guest@localhost:5672/" // 默认值
	}

	// 创建处理器
	handler := NewHandler(pythonServiceURL, rabbitMQURL, &cfg.Neo4j)

	// 设置路由
	SetupRoutes(r, handler, proxy)

	log.Printf("API server initialized with version proxy")
	log.Printf("Available versions: %v", getVersionNames(versionsConfig))
	return r
}

// loadVersionsConfig 加载版本配置
func loadVersionsConfig() *Config {
	// 尝试从配置文件加载
	configPath := "configs/versions.json"
	if _, err := os.Stat(configPath); err == nil {
		file, err := os.Open(configPath)
		if err == nil {
			defer file.Close()
			var config Config
			if json.NewDecoder(file).Decode(&config) == nil {
				return &config
			}
		}
	}

	// 默认配置
	return &Config{
		Versions: map[string]VersionInfo{
			"v1": {
				Port:        8000,
				Name:        "Version 1.0",
				Description: "Basic Version",
				Enabled:     true,
			},
			"v2": {
				Port:        8002,
				Name:        "Version 2.0",
				Description: "Enhanced Version",
				Enabled:     true,
			},
		},
	}
}

// getVersionNames 获取版本名称列表
func getVersionNames(config *Config) []string {
	var names []string
	for version, info := range config.Versions {
		if info.Enabled {
			names = append(names, version)
		}
	}
	return names
}
