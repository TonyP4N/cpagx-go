package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

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

	// 打开文件
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
		return
	}
	defer src.Close()

	// 创建multipart请求体
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// 添加文件
	part, err := writer.CreateFormFile("file", file.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create form file"})
		return
	}
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
	url := fmt.Sprintf("%s/generate", h.pythonService.BaseURL)
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
