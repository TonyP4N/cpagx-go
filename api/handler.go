package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/services"
	"github.com/gin-gonic/gin"
)

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
	messageQueue  *services.MessageQueueService
}

// NewHandler 创建新的处理器
func NewHandler(pythonServiceURL string, rabbitMQURL string) *Handler {
	// 创建消息队列服务
	messageQueue, err := services.NewMessageQueueService(rabbitMQURL, "cpag_generation")
	if err != nil {
		// 如果消息队列连接失败，记录错误但继续运行（降级到直接调用）
		fmt.Printf("Warning: Failed to connect to message queue: %v\n", err)
		messageQueue = nil
	}

	return &Handler{
		pythonService: &PythonServiceConfig{
			BaseURL: pythonServiceURL,
			Timeout: 30 * time.Second,
		},
		messageQueue: messageQueue,
	}
}

// GenerateCPAG 使用消息队列生成CPAG
func (h *Handler) GenerateCPAG(c *gin.Context) {
	// 获取上传的文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	// 获取其他参数
	deviceMapStr := c.PostForm("device_map")
	if deviceMapStr == "" {
		deviceMapStr = "{}"
	}

	rulesStr := c.PostForm("rules")
	if rulesStr == "" {
		rulesStr = "[]"
	}

	outputFormat := c.PostForm("output_format")
	if outputFormat == "" {
		outputFormat = "tcity"
	}

	// 生成任务ID
	taskID := generateTaskID()

	// 保存文件到临时目录
	tempFilePath, err := saveUploadedFile(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save uploaded file"})
		return
	}

	// 创建任务消息
	taskMessage := &services.TaskMessage{
		TaskID:     taskID,
		Type:       "cpag_generation",
		CreatedAt:  time.Now(),
		Priority:   1,
		MaxRetries: 3,
		Data: map[string]interface{}{
			"file_path":     tempFilePath,
			"file_name":     file.Filename,
			"device_map":    deviceMapStr,
			"rules":         rulesStr,
			"output_format": outputFormat,
		},
	}

	// 尝试使用消息队列发送任务
	if h.messageQueue != nil {
		if err := h.messageQueue.PublishTask(taskMessage); err != nil {
			fmt.Printf("Warning: Failed to publish to message queue: %v, falling back to direct call\n", err)
			// 降级到直接调用Python服务
			h.directCallPythonService(c, file, deviceMapStr, rulesStr, outputFormat, taskID)
		}

		// 消息队列发送成功，返回任务ID
		response := CPAGGenerationResponse{
			ID:        taskID,
			Status:    "queued",
			CreatedAt: time.Now(),
		}
		c.JSON(http.StatusOK, response)
		return
	}

	// 消息队列不可用，直接调用Python服务
	h.directCallPythonService(c, file, deviceMapStr, rulesStr, outputFormat, taskID)
}

// directCallPythonService 直接调用Python服务的降级方法
func (h *Handler) directCallPythonService(c *gin.Context, file *multipart.FileHeader, deviceMapStr, rulesStr, outputFormat, taskID string) {
	url := fmt.Sprintf("%s/generate", h.pythonService.BaseURL)

	// 创建multipart请求体
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// 添加文件
	part, err := writer.CreateFormFile("file", file.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create form file"})
		return
	}

	// 重新打开文件
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
		return
	}
	defer src.Close()

	_, err = io.Copy(part, src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to copy file data"})
		return
	}

	// 添加其他字段
	writer.WriteField("device_map", deviceMapStr)
	writer.WriteField("rules", rulesStr)
	writer.WriteField("output_format", outputFormat)
	writer.Close()

	// 发送请求到Python服务
	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: h.pythonService.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to call Python service: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.JSON(resp.StatusCode, gin.H{"error": fmt.Sprintf("Python service error: %s", string(body))})
		return
	}

	// 解析响应
	var response CPAGGenerationResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetCPAGStatus 获取CPAG生成状态
func (h *Handler) GetCPAGStatus(c *gin.Context) {
	taskID := c.Param("id")

	// 调用Python服务获取状态
	url := fmt.Sprintf("%s/status/%s", h.pythonService.BaseURL, taskID)
	resp, err := http.Get(url)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to call Python service: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.JSON(resp.StatusCode, gin.H{"error": fmt.Sprintf("Python service error: %s", string(body))})
		return
	}

	// 直接转发响应
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetCPAGResult 获取CPAG生成结果
func (h *Handler) GetCPAGResult(c *gin.Context) {
	taskID := c.Param("id")

	// 调用Python服务获取结果
	url := fmt.Sprintf("%s/result/%s", h.pythonService.BaseURL, taskID)
	resp, err := http.Get(url)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to call Python service: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		c.JSON(resp.StatusCode, gin.H{"error": fmt.Sprintf("Python service error: %s", string(body))})
		return
	}

	// 直接转发响应
	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response"})
		return
	}

	c.JSON(http.StatusOK, result)
}

// AnalyzeCPAG 对已生成的CPAG进行二次分析
func (h *Handler) AnalyzeCPAG(c *gin.Context) {
	// TODO: 调用internal/analyzer进行图分析
	c.JSON(http.StatusOK, gin.H{
		"analysis": "CPAG analysis results",
	})
}

// generateTaskID 生成唯一的任务ID
func generateTaskID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// saveUploadedFile 保存上传的文件到临时目录
func saveUploadedFile(file *multipart.FileHeader) (string, error) {
	// 创建临时目录
	tempDir := os.TempDir()
	cpagDir := filepath.Join(tempDir, "cpagx")
	if err := os.MkdirAll(cpagDir, 0755); err != nil {
		return "", err
	}

	// 生成临时文件路径
	tempFile := filepath.Join(cpagDir, file.Filename)

	// 保存文件
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	dst, err := os.Create(tempFile)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return "", err
	}

	return tempFile, nil
}
