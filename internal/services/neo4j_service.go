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

// NewNeo4jService 创建Neo4j服务
func NewNeo4jService(cfg *config.Neo4jConfig) (*Neo4jService, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("neo4j is disabled in configuration")
	}

	driver, err := neo4j.NewDriverWithContext(
		cfg.URI,
		neo4j.BasicAuth(cfg.Username, cfg.Password, ""),
		func(c *neo4j.Config) {
			c.MaxConnectionLifetime = cfg.Timeout
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create neo4j driver: %w", err)
	}

	service := &Neo4jService{
		driver: driver,
		config: cfg,
	}

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if err := service.TestConnection(ctx); err != nil {
		driver.Close(ctx)
		return nil, fmt.Errorf("failed to connect to neo4j: %w", err)
	}

	log.Printf("Connected to Neo4j at %s", cfg.URI)
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
		WITH n.task_id AS task_id, n.timestamp AS timestamp, count(n) AS node_count
		MATCH (src:CPAGNode {task_id: task_id})-[r:ATTACKS]->(dst:CPAGNode {task_id: task_id})
		WITH task_id, timestamp, node_count, count(r) AS edge_count
		RETURN task_id, timestamp, node_count, edge_count
		ORDER BY timestamp DESC
		LIMIT $limit
	`

	result, err := session.Run(ctx, query, map[string]interface{}{"limit": limit})
	if err != nil {
		return nil, fmt.Errorf("failed to query task list: %w", err)
	}

	var tasks []TaskInfo
	for result.Next(ctx) {
		record := result.Record()
		taskID, _ := record.Get("task_id")
		timestamp, _ := record.Get("timestamp")
		nodeCount, _ := record.Get("node_count")
		edgeCount, _ := record.Get("edge_count")

		// 解析时间戳
		var parsedTime time.Time
		if timeStr, ok := timestamp.(string); ok {
			if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
				parsedTime = t
			}
		}

		tasks = append(tasks, TaskInfo{
			TaskID:    taskID.(string),
			Timestamp: parsedTime,
			NodeCount: int(nodeCount.(int64)),
			EdgeCount: int(edgeCount.(int64)),
		})
	}

	return tasks, result.Err()
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
		RETURN n.id AS id, n.task_id AS task_id, n.node_type AS node_type, n.properties AS properties
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

	// 获取边
	edgeQuery := `
		MATCH (src:CPAGNode {task_id: $task_id})-[r:ATTACKS]->(dst:CPAGNode {task_id: $task_id})
		RETURN src.id AS source, dst.id AS target, r.task_id AS task_id, r.edge_type AS edge_type, r.properties AS properties
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
