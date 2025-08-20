package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/config"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Neo4jService Neo4j服务
type Neo4jService struct {
	driver neo4j.DriverWithContext
	config *config.Neo4jConfig
}

// Node 图节点结构
type Node struct {
	ID         string                 `json:"id"`
	TaskID     string                 `json:"task_id"`
	NodeType   string                 `json:"node_type"`
	Properties map[string]interface{} `json:"properties"`
}

// Edge 图边结构
type Edge struct {
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	TaskID     string                 `json:"task_id"`
	EdgeType   string                 `json:"edge_type"`
	Properties map[string]interface{} `json:"properties"`
}

// GraphData 图数据结构
type GraphData struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// TaskInfo 任务信息
type TaskInfo struct {
	TaskID    string    `json:"task_id"`
	Timestamp time.Time `json:"timestamp"`
	NodeCount int       `json:"node_count"`
	EdgeCount int       `json:"edge_count"`
}

// tryNeo4jConnection 尝试连接到指定的Neo4j URI
func tryNeo4jConnection(uri, username, password string, timeout time.Duration) (neo4j.DriverWithContext, error) {
	driver, err := neo4j.NewDriverWithContext(
		uri,
		neo4j.BasicAuth(username, password, ""),
		func(c *neo4j.Config) {
			c.MaxConnectionLifetime = timeout
		},
	)
	if err != nil {
		return nil, err
	}

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	session := driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	_, err = session.Run(ctx, "RETURN 1", nil)
	if err != nil {
		driver.Close(ctx)
		return nil, err
	}

	return driver, nil
}

// NewNeo4jService 创建Neo4j服务 - 支持智能连接
func NewNeo4jService(cfg *config.Neo4jConfig) (*Neo4jService, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("neo4j is disabled in configuration")
	}

	// 智能Neo4j连接 - 尝试多个可能的URI
	candidateURIs := []string{
		cfg.URI,                 // 首先尝试配置的URI
		"bolt://localhost:7689", // 本地映射端口
		"bolt://localhost:7687", // 默认端口
		"bolt://neo4j:7687",     // Docker内部地址
		"bolt://127.0.0.1:7689", // 备用本地地址
		"bolt://127.0.0.1:7687", // 备用默认地址
	}

	var driver neo4j.DriverWithContext
	var workingURI string
	var lastErr error

	for _, uri := range candidateURIs {
		log.Printf("Trying Neo4j connection to: %s", uri)

		testDriver, err := tryNeo4jConnection(uri, cfg.Username, cfg.Password, cfg.Timeout)
		if err != nil {
			log.Printf("Failed to connect to %s: %v", uri, err)
			lastErr = err
			continue
		}

		driver = testDriver
		workingURI = uri
		log.Printf("Successfully connected to Neo4j: %s", uri)
		break
	}

	if driver == nil {
		return nil, fmt.Errorf("failed to connect to any Neo4j URI, last error: %w", lastErr)
	}

	// 更新配置中的URI为实际工作的URI
	updatedCfg := *cfg
	updatedCfg.URI = workingURI

	service := &Neo4jService{
		driver: driver,
		config: &updatedCfg,
	}

	log.Printf("Neo4j service initialized with URI: %s", workingURI)
	return service, nil
}

// Close 关闭连接
func (s *Neo4jService) Close(ctx context.Context) error {
	return s.driver.Close(ctx)
}

// TestConnection 测试连接
func (s *Neo4jService) TestConnection(ctx context.Context) error {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: s.config.Database,
	})
	defer session.Close(ctx)

	_, err := session.Run(ctx, "RETURN 1", nil)
	return err
}

// GetTaskList 获取任务列表
func (s *Neo4jService) GetTaskList(ctx context.Context, limit int) ([]TaskInfo, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: s.config.Database,
	})
	defer session.Close(ctx)

	query := `
		MATCH (n:CPAGNode)
		WHERE n.task_id IS NOT NULL
		WITH n.task_id AS task_id, min(n.created_at) AS timestamp, count(DISTINCT n) AS node_count
		OPTIONAL MATCH (src:CPAGNode {task_id: task_id})-[r]->(dst:CPAGNode {task_id: task_id})
		RETURN task_id, timestamp, node_count, count(DISTINCT r) AS edge_count
		ORDER BY timestamp DESC
		LIMIT $limit
	`

	log.Printf("Executing Neo4j query with limit %d: %s", limit, query)
	result, err := session.Run(ctx, query, map[string]interface{}{"limit": limit})
	if err != nil {
		log.Printf("Neo4j query failed: %v", err)
		return nil, fmt.Errorf("failed to query task list: %w", err)
	}
	log.Printf("Neo4j query executed successfully")

	var tasks []TaskInfo
	for result.Next(ctx) {
		record := result.Record()

		// 使用安全的类型转换和详细的错误日志
		taskIDRaw, hasTaskID := record.Get("task_id")
		timestampRaw, hasTimestamp := record.Get("timestamp")
		nodeCountRaw, hasNodeCount := record.Get("node_count")
		edgeCountRaw, hasEdgeCount := record.Get("edge_count")

		log.Printf("Neo4j record - taskID: %v (%T), timestamp: %v (%T), nodeCount: %v (%T), edgeCount: %v (%T)",
			taskIDRaw, taskIDRaw, timestampRaw, timestampRaw, nodeCountRaw, nodeCountRaw, edgeCountRaw, edgeCountRaw)

		if !hasTaskID || !hasNodeCount || !hasEdgeCount {
			log.Printf("Missing required fields in Neo4j record")
			continue
		}

		// 安全的字符串转换
		var taskID string
		if taskIDStr, ok := taskIDRaw.(string); ok {
			taskID = taskIDStr
		} else {
			log.Printf("TaskID is not a string: %v (%T)", taskIDRaw, taskIDRaw)
			continue
		}

		// 解析时间戳
		var parsedTime time.Time
		if hasTimestamp {
			if timeStr, ok := timestampRaw.(string); ok {
				// 尝试多种时间格式
				timeFormats := []string{
					time.RFC3339,                 // 2006-01-02T15:04:05Z07:00
					time.RFC3339Nano,             // 2006-01-02T15:04:05.999999999Z07:00
					"2006-01-02T15:04:05.999999", // Neo4j 格式：2025-08-19T06:12:56.051714
					"2006-01-02T15:04:05",        // 基本ISO格式
				}

				var parseErr error
				for _, format := range timeFormats {
					if t, err := time.Parse(format, timeStr); err == nil {
						parsedTime = t
						log.Printf("Successfully parsed timestamp using format %s: %v", format, timeStr)
						break
					} else {
						parseErr = err
					}
				}

				if parsedTime.IsZero() {
					log.Printf("Failed to parse timestamp with all formats: %v, last error: %v", timeStr, parseErr)
				}
			} else {
				log.Printf("Timestamp is not a string: %v (%T)", timestampRaw, timestampRaw)
			}
		}

		// 安全的整数转换
		var nodeCount, edgeCount int
		if nc, ok := nodeCountRaw.(int64); ok {
			nodeCount = int(nc)
		} else {
			log.Printf("NodeCount is not int64: %v (%T)", nodeCountRaw, nodeCountRaw)
			continue
		}

		if ec, ok := edgeCountRaw.(int64); ok {
			edgeCount = int(ec)
		} else {
			log.Printf("EdgeCount is not int64: %v (%T)", edgeCountRaw, edgeCountRaw)
			continue
		}

		log.Printf("Successfully parsed task: %s, nodes: %d, edges: %d, time: %v", taskID, nodeCount, edgeCount, parsedTime)

		tasks = append(tasks, TaskInfo{
			TaskID:    taskID,
			Timestamp: parsedTime,
			NodeCount: nodeCount,
			EdgeCount: edgeCount,
		})
	}

	log.Printf("Final task count: %d", len(tasks))
	if resultErr := result.Err(); resultErr != nil {
		log.Printf("Neo4j result error: %v", resultErr)
		return tasks, resultErr
	}
	return tasks, nil
}

// GetGraphData 获取指定任务的图数据
func (s *Neo4jService) GetGraphData(ctx context.Context, taskID string) (*GraphData, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: s.config.Database,
	})
	defer session.Close(ctx)

	// 获取节点
	nodeQuery := `
		MATCH (n:CPAGNode {task_id: $task_id})
		RETURN n.id AS id, n.task_id AS task_id, n.type AS node_type, properties(n) AS properties
	`

	nodeResult, err := session.Run(ctx, nodeQuery, map[string]interface{}{"task_id": taskID})
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w", err)
	}

	var nodes []Node
	for nodeResult.Next(ctx) {
		record := nodeResult.Record()
		id, _ := record.Get("id")
		taskIDField, _ := record.Get("task_id")
		nodeType, _ := record.Get("node_type")
		properties, _ := record.Get("properties")

		var props map[string]interface{}
		if properties != nil {
			if propsBytes, err := json.Marshal(properties); err == nil {
				json.Unmarshal(propsBytes, &props)
			}
		}

		nodes = append(nodes, Node{
			ID:         id.(string),
			TaskID:     taskIDField.(string),
			NodeType:   nodeType.(string),
			Properties: props,
		})
	}

	if err := nodeResult.Err(); err != nil {
		return nil, fmt.Errorf("error reading nodes: %w", err)
	}

	// 获取边 - 支持所有关系类型
	edgeQuery := `
		MATCH (src:CPAGNode {task_id: $task_id})-[r]->(dst:CPAGNode {task_id: $task_id})
		RETURN src.id AS source, dst.id AS target, src.task_id AS task_id, type(r) AS edge_type, properties(r) AS properties
	`

	edgeResult, err := session.Run(ctx, edgeQuery, map[string]interface{}{"task_id": taskID})
	if err != nil {
		return nil, fmt.Errorf("failed to query edges: %w", err)
	}

	var edges []Edge
	for edgeResult.Next(ctx) {
		record := edgeResult.Record()
		source, _ := record.Get("source")
		target, _ := record.Get("target")
		taskIDField, _ := record.Get("task_id")
		edgeType, _ := record.Get("edge_type")
		properties, _ := record.Get("properties")

		var props map[string]interface{}
		if properties != nil {
			if propsBytes, err := json.Marshal(properties); err == nil {
				json.Unmarshal(propsBytes, &props)
			}
		}

		edges = append(edges, Edge{
			Source:     source.(string),
			Target:     target.(string),
			TaskID:     taskIDField.(string),
			EdgeType:   edgeType.(string),
			Properties: props,
		})
	}

	if err := edgeResult.Err(); err != nil {
		return nil, fmt.Errorf("error reading edges: %w", err)
	}

	// Ensure edges is never nil
	if edges == nil {
		edges = []Edge{}
	}

	return &GraphData{
		Nodes: nodes,
		Edges: edges,
	}, nil
}

// DeleteTask 删除指定任务的数据
func (s *Neo4jService) DeleteTask(ctx context.Context, taskID string) error {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: s.config.Database,
	})
	defer session.Close(ctx)

	query := `
		MATCH (n:CPAGNode {task_id: $task_id})
		DETACH DELETE n
	`

	_, err := session.Run(ctx, query, map[string]interface{}{"task_id": taskID})
	if err != nil {
		return fmt.Errorf("failed to delete task: %w", err)
	}

	return nil
}

// GetHealthStatus 获取健康状态
func (s *Neo4jService) GetHealthStatus(ctx context.Context) map[string]interface{} {
	status := map[string]interface{}{
		"connected": false,
		"database":  s.config.Database,
		"uri":       s.config.URI,
	}

	if err := s.TestConnection(ctx); err != nil {
		status["error"] = err.Error()
	} else {
		status["connected"] = true
	}

	return status
}

// GetConfig 获取配置信息
func (s *Neo4jService) GetConfig() *config.Neo4jConfig {
	return s.config
}
