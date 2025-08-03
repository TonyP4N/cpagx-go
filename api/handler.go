package api

import (
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
)

// CPAGGenerationRequest 请求结构
type CPAGGenerationRequest struct {
	PCAPFile     string            `json:"pcap_file"`
	DeviceMap    map[string]string `json:"device_map"`
	Rules        []string          `json:"rules"`
	OutputFormat string            `json:"output_format"` // "tcity" or "internal"
}

// CPAGGenerationResponse 响应结构
type CPAGGenerationResponse struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ResultURL string    `json:"result_url,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// PythonServiceConfig Python微服务配置
type PythonServiceConfig struct {
	BaseURL string
	Timeout time.Duration
}

// Handler API处理器
type Handler struct {
	pythonService *PythonServiceConfig
}

// NewHandler 创建新的处理器
func NewHandler(pythonServiceURL string) *Handler {
	return &Handler{
		pythonService: &PythonServiceConfig{
			BaseURL: pythonServiceURL,
			Timeout: 30 * time.Second,
		},
	}
}

// GenerateCPAG 调用Python服务生成CPAG
func (h *Handler) GenerateCPAG(c *fiber.Ctx) error {
	var req CPAGGenerationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// TODO: 调用Python微服务的/generate接口
	// 1. 发送请求到Python服务
	// 2. 处理异步响应
	// 3. 返回任务ID供前端轮询

	response := CPAGGenerationResponse{
		ID:        "task_123",
		Status:    "processing",
		CreatedAt: time.Now(),
	}

	return c.JSON(response)
}

// GetCPAGStatus 获取CPAG生成状态
func (h *Handler) GetCPAGStatus(c *fiber.Ctx) error {
	taskID := c.Params("id")

	// TODO: 查询Python服务获取任务状态
	// 如果完成，返回结果URL

	return c.JSON(fiber.Map{
		"id":     taskID,
		"status": "completed",
		"result": "http://localhost:8080/api/cpag/result/task_123",
	})
}

// GetCPAGResult 获取CPAG生成结果
func (h *Handler) GetCPAGResult(c *fiber.Ctx) error {
	taskID := c.Params("id")

	// TODO: 从Python服务或本地缓存获取结果
	// 返回T-CITY格式的JSON

	return c.JSON(fiber.Map{
		"task_id": taskID,
		"cpag":    "T-CITY JSON content here",
	})
}

// AnalyzeCPAG 对已生成的CPAG进行二次分析
func (h *Handler) AnalyzeCPAG(c *fiber.Ctx) error {
	// TODO: 调用internal/analyzer进行图分析
	return c.JSON(fiber.Map{
		"analysis": "CPAG analysis results",
	})
}
