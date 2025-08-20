package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// VersionProxy 版本代理服务
type VersionProxy struct {
	versions map[string]*httputil.ReverseProxy
	config   *Config
}

// Config 代理配置
type Config struct {
	Versions map[string]VersionInfo `json:"versions"`
}

// VersionInfo 版本信息
type VersionInfo struct {
	Port        int    `json:"port"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// NewVersionProxy 创建版本代理
func NewVersionProxy(config *Config) *VersionProxy {
	proxy := &VersionProxy{
		versions: make(map[string]*httputil.ReverseProxy),
		config:   config,
	}

	// 为每个版本创建反向代理
	for version, info := range config.Versions {
		if info.Enabled {
			// 在Docker环境中使用容器名称
			targetURL := fmt.Sprintf("http://python-cpag-generator:%d", info.Port)
			target, err := url.Parse(targetURL)
			if err != nil {
				continue
			}

			reverseProxy := httputil.NewSingleHostReverseProxy(target)
			reverseProxy.ModifyResponse = proxy.modifyResponse
			reverseProxy.ErrorHandler = proxy.errorHandler

			proxy.versions[version] = reverseProxy
		}
	}

	return proxy
}

// modifyResponse 修改响应
func (p *VersionProxy) modifyResponse(resp *http.Response) error {
	// 添加版本信息到响应头
	resp.Header.Set("X-Cpag-Version", "v1") // 这里需要根据实际版本设置
	return nil
}

// errorHandler 错误处理
func (p *VersionProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)

	errorResponse := map[string]interface{}{
		"error":   "Service Unavailable",
		"message": "Python service is not available",
		"details": err.Error(),
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// ProxyToVersion 代理到指定版本
func (p *VersionProxy) ProxyToVersion(version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		proxy, exists := p.versions[version]
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Version Not Found",
				"message": fmt.Sprintf("Version %s is not available", version),
			})
			return
		}

		// 设置版本信息到上下文
		c.Set("version", version)

		// 修改请求路径，移除 /api/v1 前缀
		originalPath := c.Request.URL.Path
		if strings.HasPrefix(originalPath, "/api/v1") {
			c.Request.URL.Path = strings.TrimPrefix(originalPath, "/api/v1")
		} else if strings.HasPrefix(originalPath, "/api/v2") {
			c.Request.URL.Path = strings.TrimPrefix(originalPath, "/api/v2")
		}

		// 对于 v2 版本的 CPAG 生成请求，添加 Neo4j 配置参数
		fmt.Printf("Proxy check: version=%s, method=%s, path=%s\n", version, c.Request.Method, c.Request.URL.Path)
		if version == "v2" && c.Request.Method == "POST" && strings.Contains(c.Request.URL.Path, "/cpag/generate") {
			fmt.Printf("Calling enhanceV2Request\n")
			p.enhanceV2Request(c)
		}

		// 执行代理
		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

// HealthCheck 健康检查
func (p *VersionProxy) HealthCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		version := c.Param("version")

		info, exists := p.config.Versions[version]
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Version Not Found",
				"message": fmt.Sprintf("Version %s is not available", version),
			})
			return
		}

		// 检查服务健康状态
		healthURL := fmt.Sprintf("http://python-cpag-generator:%d/health", info.Port)
		resp, err := http.Get(healthURL)

		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"version": version,
				"status":  "unhealthy",
				"error":   err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			c.JSON(http.StatusOK, gin.H{
				"version": version,
				"status":  "healthy",
				"port":    info.Port,
			})
		} else {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"version":     version,
				"status":      "unhealthy",
				"status_code": resp.StatusCode,
			})
		}
	}
}

// SwitchVersion 切换版本
func (p *VersionProxy) SwitchVersion() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Version string `json:"version" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid Request",
				"message": err.Error(),
			})
			return
		}

		// 检查版本是否存在且启用
		info, exists := p.config.Versions[req.Version]
		if !exists || !info.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid Version",
				"message": fmt.Sprintf("Version %s is not available or disabled", req.Version),
			})
			return
		}

		// 检查服务健康状态
		healthURL := fmt.Sprintf("http://python-cpag-generator:%d/health", info.Port)
		resp, err := http.Get(healthURL)

		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service Unavailable",
				"message": fmt.Sprintf("Version %s service is not available", req.Version),
			})
			return
		}
		defer resp.Body.Close()

		// 返回版本信息
		c.JSON(http.StatusOK, gin.H{
			"version":     req.Version,
			"name":        info.Name,
			"description": info.Description,
			"port":        info.Port,
			"status":      "available",
		})
	}
}

// GetVersions 获取所有可用版本
func (p *VersionProxy) GetVersions() gin.HandlerFunc {
	return func(c *gin.Context) {
		versions := make(map[string]interface{})

		for version, info := range p.config.Versions {
			// 检查服务健康状态
			healthURL := fmt.Sprintf("http://python-cpag-generator:%d/health", info.Port)
			resp, err := http.Get(healthURL)

			status := "unhealthy"
			if err == nil && resp.StatusCode == http.StatusOK {
				status = "healthy"
			}
			if resp != nil {
				resp.Body.Close()
			}

			versions[version] = gin.H{
				"name":        info.Name,
				"description": info.Description,
				"port":        info.Port,
				"enabled":     info.Enabled,
				"status":      status,
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"versions": versions,
		})
	}
}

// GetTaskList 获取任务列表
func (p *VersionProxy) GetTaskList() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前版本（从查询参数或默认使用v1）
		version := c.Query("version")

		// 如果没有指定版本，则获取所有版本的任务
		if version == "" {
			var allTasks []interface{}

			// 遍历所有可用版本
			for _, info := range p.config.Versions {
				if !info.Enabled {
					continue
				}

				// 获取该版本的任务列表
				taskListURL := fmt.Sprintf("http://python-cpag-generator:%d/cpag/tasks", info.Port)
				resp, err := http.Get(taskListURL)

				if err != nil {
					// 如果某个版本不可用，继续处理其他版本
					continue
				}

				var tasks []interface{}
				if err := json.NewDecoder(resp.Body).Decode(&tasks); err != nil {
					resp.Body.Close()
					continue
				}
				resp.Body.Close()

				// 将任务添加到总列表中
				allTasks = append(allTasks, tasks...)
			}

			// 对合并的任务按创建时间排序
			sort.Slice(allTasks, func(i, j int) bool {
				// 尝试从任务中提取created_at字段
				taskI, okI := allTasks[i].(map[string]interface{})
				taskJ, okJ := allTasks[j].(map[string]interface{})

				if !okI || !okJ {
					return false
				}

				createdAtI, okI := taskI["created_at"].(string)
				createdAtJ, okJ := taskJ["created_at"].(string)

				if !okI || !okJ {
					return false
				}

				// 标准化时间格式（确保都有Z后缀）
				if !strings.HasSuffix(createdAtI, "Z") {
					createdAtI += "Z"
				}
				if !strings.HasSuffix(createdAtJ, "Z") {
					createdAtJ += "Z"
				}

				// 按时间倒序排列（最新的在前）
				return createdAtI > createdAtJ
			})

			// 返回所有版本的任务
			c.JSON(http.StatusOK, allTasks)
			return
		}

		// 如果指定了版本，则只返回该版本的任务
		info, exists := p.config.Versions[version]
		if !exists || !info.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid Version",
				"message": fmt.Sprintf("Version %s is not available", version),
			})
			return
		}

		// 代理到对应版本的任务列表端点
		taskListURL := fmt.Sprintf("http://python-cpag-generator:%d/cpag/tasks", info.Port)
		resp, err := http.Get(taskListURL)

		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service Unavailable",
				"message": fmt.Sprintf("Cannot connect to version %s service", version),
			})
			return
		}
		defer resp.Body.Close()

		// 转发响应
		c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
	}
}

// DownloadFile 下载文件
func (p *VersionProxy) DownloadFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取参数
		taskID := c.Param("task_id")
		filename := c.Param("filename")
		version := c.Query("version")
		if version == "" {
			version = "v1"
		}

		info, exists := p.config.Versions[version]
		if !exists || !info.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid Version",
				"message": fmt.Sprintf("Version %s is not available", version),
			})
			return
		}

		// 代理到对应版本的文件下载端点
		downloadURL := fmt.Sprintf("http://python-cpag-generator:%d/cpag/download/%s/%s", info.Port, taskID, filename)
		resp, err := http.Get(downloadURL)

		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service Unavailable",
				"message": fmt.Sprintf("Cannot connect to version %s service", version),
			})
			return
		}
		defer resp.Body.Close()

		// 转发响应
		c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
	}
}

// GetBatchTaskStatus 批量获取任务状态
func (p *VersionProxy) GetBatchTaskStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前版本（从查询参数或默认使用v1）
		version := c.Query("version")
		if version == "" {
			version = "v1"
		}

		// 获取任务ID列表
		taskIds := c.Query("task_ids")
		if taskIds == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Missing task_ids parameter",
				"message": "task_ids parameter is required",
			})
			return
		}

		info, exists := p.config.Versions[version]
		if !exists || !info.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid Version",
				"message": fmt.Sprintf("Version %s is not available", version),
			})
			return
		}

		// 代理到对应版本的批量状态查询端点
		batchStatusURL := fmt.Sprintf("http://python-cpag-generator:%d/cpag/status/batch?task_ids=%s", info.Port, taskIds)
		resp, err := http.Get(batchStatusURL)

		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service Unavailable",
				"message": fmt.Sprintf("Cannot connect to version %s service", version),
			})
			return
		}
		defer resp.Body.Close()

		// 转发响应
		c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
	}
}

// GetQueueStatus 获取任务队列状态
func (p *VersionProxy) GetQueueStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前版本（从查询参数或默认使用v1）
		version := c.Query("version")
		if version == "" {
			version = "v1"
		}

		info, exists := p.config.Versions[version]
		if !exists || !info.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid Version",
				"message": fmt.Sprintf("Version %s is not available", version),
			})
			return
		}

		// 代理到对应版本的队列状态端点
		queueStatusURL := fmt.Sprintf("http://python-cpag-generator:%d/cpag/queue/status", info.Port)
		resp, err := http.Get(queueStatusURL)

		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service Unavailable",
				"message": fmt.Sprintf("Cannot connect to version %s service", version),
			})
			return
		}
		defer resp.Body.Close()

		// 转发响应
		c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
	}
}

// enhanceV2Request 为 v2 请求添加 Neo4j 配置参数
func (p *VersionProxy) enhanceV2Request(c *gin.Context) {
	fmt.Printf("enhanceV2Request called for path: %s, content-type: %s\n", c.Request.URL.Path, c.GetHeader("Content-Type"))

	// 只处理 multipart form-data 请求
	if !strings.Contains(c.GetHeader("Content-Type"), "multipart/form-data") {
		fmt.Printf("Skipping non-multipart request\n")
		return
	}

	// 解析 multipart form
	if err := c.Request.ParseMultipartForm(300 << 20); err != nil { // 300MB limit
		fmt.Printf("Warning: Failed to parse multipart form: %v\n", err)
		return
	}

	// 添加 Neo4j 配置到表单数据
	form := c.Request.MultipartForm
	if form.Value == nil {
		form.Value = make(map[string][]string)
	}

	// 添加 Neo4j 配置字段
	neo4jURI := os.Getenv("NEO4J_URI")
	if neo4jURI == "" {
		neo4jURI = "bolt://neo4j:7687"
	}

	neo4jUser := os.Getenv("NEO4J_USER")
	if neo4jUser == "" {
		neo4jUser = "neo4j"
	}

	neo4jPassword := os.Getenv("NEO4J_PASSWORD")
	if neo4jPassword == "" {
		neo4jPassword = "password123"
	}

	neo4jDB := os.Getenv("NEO4J_DATABASE")
	if neo4jDB == "" {
		neo4jDB = "neo4j"
	}

	// 添加配置到表单
	form.Value["neo4j_uri"] = []string{neo4jURI}
	form.Value["neo4j_user"] = []string{neo4jUser}
	form.Value["neo4j_password"] = []string{neo4jPassword}
	form.Value["neo4j_db"] = []string{neo4jDB}
	form.Value["neo4j_label"] = []string{"CPAGNode"}
	form.Value["wipe_neo4j"] = []string{"false"}

	fmt.Printf("Enhanced v2 request with Neo4j config: URI=%s, User=%s, DB=%s\n", neo4jURI, neo4jUser, neo4jDB)

	// 重新构建请求体
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// 添加文件
	if form.File != nil {
		for fieldName, files := range form.File {
			for _, fileHeader := range files {
				file, err := fileHeader.Open()
				if err != nil {
					continue
				}
				defer file.Close()

				part, err := writer.CreateFormFile(fieldName, fileHeader.Filename)
				if err != nil {
					continue
				}
				io.Copy(part, file)
			}
		}
	}

	// 添加表单字段
	for fieldName, values := range form.Value {
		for _, value := range values {
			writer.WriteField(fieldName, value)
		}
	}

	writer.Close()

	// 更新请求
	c.Request.Body = io.NopCloser(&buf)
	c.Request.ContentLength = int64(buf.Len())
	c.Request.Header.Set("Content-Type", writer.FormDataContentType())
}
