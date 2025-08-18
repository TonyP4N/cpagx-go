package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/config"
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
	neo4jService  *services.Neo4jService
}

// NewHandler 创建新的处理器
func NewHandler(pythonServiceURL string, rabbitMQURL string, neo4jConfig *config.Neo4jConfig) *Handler {
	// 创建消息队列服务
	messageQueue, err := services.NewMessageQueueService(rabbitMQURL, "cpag_generation")
	if err != nil {
		// 如果消息队列连接失败，记录错误但继续运行（降级到直接调用）
		fmt.Printf("Warning: Failed to connect to message queue: %v\n", err)
		messageQueue = nil
	}

	// 创建Neo4j服务（带重试逻辑）
	var neo4jService *services.Neo4jService
	if neo4jConfig != nil && neo4jConfig.Enabled {
		// 重试连接Neo4j，最多重试5次，每次间隔5秒
		for i := 0; i < 5; i++ {
			neo4jService, err = services.NewNeo4jService(neo4jConfig)
			if err == nil {
				fmt.Printf("Successfully connected to Neo4j on attempt %d\n", i+1)
				break
			}
			fmt.Printf("Warning: Failed to connect to Neo4j (attempt %d/5): %v\n", i+1, err)
			if i < 4 { // 不是最后一次尝试
				time.Sleep(5 * time.Second)
			}
		}
		if err != nil {
			fmt.Printf("Warning: Failed to connect to Neo4j after 5 attempts, continuing without Neo4j\n")
			neo4jService = nil
		}
	}

	return &Handler{
		pythonService: &PythonServiceConfig{
			BaseURL: pythonServiceURL,
			Timeout: 30 * time.Second,
		},
		messageQueue: messageQueue,
		neo4jService: neo4jService,
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

	// 获取Neo4j配置
	neo4jConfig := map[string]interface{}{
		"neo4j_uri":      os.Getenv("NEO4J_URI"),
		"neo4j_user":     os.Getenv("NEO4J_USER"),
		"neo4j_password": os.Getenv("NEO4J_PASSWORD"),
		"neo4j_db":       os.Getenv("NEO4J_DATABASE"),
		"neo4j_label":    "CPAGNode",
		"wipe_neo4j":     false,
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
			"neo4j_config":  neo4jConfig,
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

	// 添加Neo4j配置字段
	writer.WriteField("neo4j_uri", os.Getenv("NEO4J_URI"))
	writer.WriteField("neo4j_user", os.Getenv("NEO4J_USER"))
	writer.WriteField("neo4j_password", os.Getenv("NEO4J_PASSWORD"))
	writer.WriteField("neo4j_db", os.Getenv("NEO4J_DATABASE"))
	writer.WriteField("neo4j_label", "CPAGNode")
	writer.WriteField("wipe_neo4j", "false")

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

// GetGraphTasks 获取Neo4j中的任务列表
func (h *Handler) GetGraphTasks(c *gin.Context) {
	if h.neo4jService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Neo4j service not available"})
		return
	}

	// 获取限制参数
	limitStr := c.DefaultQuery("limit", "20")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 20
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tasks, err := h.neo4jService.GetTaskList(ctx, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get task list: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tasks": tasks,
		"total": len(tasks),
	})
}

// GetGraphData 获取指定任务的图数据
func (h *Handler) GetGraphData(c *gin.Context) {
	if h.neo4jService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Neo4j service not available"})
		return
	}

	taskID := c.Param("task_id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Task ID is required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	graphData, err := h.neo4jService.GetGraphData(ctx, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get graph data: %v", err)})
		return
	}

	c.JSON(http.StatusOK, graphData)
}

// DeleteGraphTask 删除指定任务的图数据
func (h *Handler) DeleteGraphTask(c *gin.Context) {
	if h.neo4jService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Neo4j service not available"})
		return
	}

	taskID := c.Param("task_id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Task ID is required"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := h.neo4jService.DeleteTask(ctx, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete task: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task deleted successfully"})
}

// GetNeo4jHealth 获取Neo4j健康状态
func (h *Handler) GetNeo4jHealth(c *gin.Context) {
	if h.neo4jService == nil {
		c.JSON(http.StatusOK, gin.H{
			"neo4j": gin.H{
				"enabled":   false,
				"connected": false,
				"message":   "Neo4j service not configured",
			},
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthStatus := h.neo4jService.GetHealthStatus(ctx)
	c.JSON(http.StatusOK, gin.H{"neo4j": healthStatus})
}

// GetNeo4jBrowserURL 获取Neo4j Browser访问URL
func (h *Handler) GetNeo4jBrowserURL(c *gin.Context) {
	if h.neo4jService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Neo4j service not available"})
		return
	}

	// 根据docker-compose.yml的端口映射，Neo4j Browser的外部访问端口是7476
	// 内部端口7474映射到外部端口7476
	browserURL := "http://localhost:7476/browser/"

	c.JSON(http.StatusOK, gin.H{
		"browser_url": browserURL,
		"database":    h.neo4jService.GetConfig().Database,
		"username":    h.neo4jService.GetConfig().Username,
	})
}
