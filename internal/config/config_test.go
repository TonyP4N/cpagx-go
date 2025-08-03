package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfigFromFile(t *testing.T) {
	// 创建临时配置文件
	tempConfig := `{
		"server": {
			"port": "8080",
			"host": "localhost",
			"read_timeout": "30s",
			"write_timeout": "30s"
		},
		"python": {
			"service_url": "http://localhost:8000",
			"timeout": "60s",
			"retries": 3
		},
		"database": {
			"type": "sqlite",
			"host": "localhost",
			"port": 0,
			"database": "test.db",
			"username": "",
			"password": ""
		},
		"cache": {
			"type": "memory",
			"ttl": "1h",
			"max_size": 1000
		}
	}`

	tempFile := "temp_config.json"
	err := os.WriteFile(tempFile, []byte(tempConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tempFile)

	// 测试加载配置
	config, err := LoadConfig(tempFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// 验证配置
	if config.Server.Port != "8080" {
		t.Errorf("Expected server port 8080, got %s", config.Server.Port)
	}
	if config.Server.Host != "localhost" {
		t.Errorf("Expected server host localhost, got %s", config.Server.Host)
	}
	if config.Python.ServiceURL != "http://localhost:8000" {
		t.Errorf("Expected Python service URL http://localhost:8000, got %s", config.Python.ServiceURL)
	}
	if config.Python.Timeout != 60*time.Second {
		t.Errorf("Expected Python timeout 60s, got %v", config.Python.Timeout)
	}
	if config.Database.Type != "sqlite" {
		t.Errorf("Expected database type sqlite, got %s", config.Database.Type)
	}
	if config.Cache.Type != "memory" {
		t.Errorf("Expected cache type memory, got %s", config.Cache.Type)
	}
	if config.Cache.MaxSize != 1000 {
		t.Errorf("Expected cache max size 1000, got %d", config.Cache.MaxSize)
	}
}

func TestValidateConfig(t *testing.T) {
	// 测试有效配置
	validConfig := &Config{
		Server: ServerConfig{
			Port: "8080",
			Host: "localhost",
		},
		Python: PythonConfig{
			ServiceURL: "http://localhost:8000",
		},
		Database: DatabaseConfig{
			Type: "sqlite",
		},
		Cache: CacheConfig{
			Type:    "memory",
			MaxSize: 1000,
		},
	}

	if err := validateConfig(validConfig); err != nil {
		t.Errorf("Valid config should not return error: %v", err)
	}

	// 测试无效配置
	invalidConfig := &Config{
		Server: ServerConfig{
			Port: "",
			Host: "",
		},
		Python: PythonConfig{
			ServiceURL: "invalid-url",
			Retries:    15,
		},
		Database: DatabaseConfig{
			Type: "invalid-db",
			Port: 70000,
		},
		Cache: CacheConfig{
			Type:    "invalid-cache",
			MaxSize: 0,
		},
	}

	err := validateConfig(invalidConfig)
	if err == nil {
		t.Error("Invalid config should return error")
	}
}

func TestValidateConfigMultipleErrors(t *testing.T) {
	invalidConfig := &Config{
		Server: ServerConfig{
			Port: "",
			Host: "",
		},
		Python: PythonConfig{
			ServiceURL: "invalid-url",
			Retries:    15,
		},
		Database: DatabaseConfig{
			Type: "invalid-db",
			Port: 70000,
		},
		Cache: CacheConfig{
			Type:    "invalid-cache",
			MaxSize: 0,
		},
	}

	err := validateConfig(invalidConfig)
	if err == nil {
		t.Error("Invalid config should return error")
		return
	}

	errorMsg := err.Error()
	expectedErrors := []string{
		"server port cannot be empty",
		"server host cannot be empty",
		"python service URL must start with http:// or https://",
		"python retries must be between 0 and 10",
		"invalid database type",
		"database port must be a valid port number",
		"invalid cache type",
		"cache max size must be greater than 0",
	}

	for _, expectedError := range expectedErrors {
		if !contains(errorMsg, expectedError) {
			t.Errorf("Error message should contain: %s", expectedError)
		}
	}
}

func TestGetServerAddress(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			Port: "8080",
			Host: "localhost",
		},
	}

	expected := "localhost:8080"
	if result := config.GetServerAddress(); result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestIsDevelopment(t *testing.T) {
	devConfig := &Config{
		Server: ServerConfig{
			Host: "localhost",
		},
	}

	if !devConfig.IsDevelopment() {
		t.Error("localhost should be considered development environment")
	}

	prodConfig := &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
		},
	}

	if prodConfig.IsDevelopment() {
		t.Error("0.0.0.0 should not be considered development environment")
	}
}

func TestIsProduction(t *testing.T) {
	prodConfig := &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
		},
		Database: DatabaseConfig{
			Type: "redis",
		},
	}

	if !prodConfig.IsProduction() {
		t.Error("0.0.0.0 with redis should be considered production environment")
	}

	devConfig := &Config{
		Server: ServerConfig{
			Host: "localhost",
		},
		Database: DatabaseConfig{
			Type: "sqlite",
		},
	}

	if devConfig.IsProduction() {
		t.Error("localhost with sqlite should not be considered production environment")
	}
}

func TestSaveConfig(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			Port:         "8080",
			Host:         "localhost",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Python: PythonConfig{
			ServiceURL: "http://localhost:8000",
			Timeout:    60 * time.Second,
			Retries:    3,
		},
		Database: DatabaseConfig{
			Type:     "sqlite",
			Host:     "localhost",
			Port:     0,
			Database: "test.db",
			Username: "",
			Password: "",
		},
		Cache: CacheConfig{
			Type:    "memory",
			TTL:     1 * time.Hour,
			MaxSize: 1000,
		},
	}

	tempFile := "temp_save_config.json"
	defer os.Remove(tempFile)

	// 保存配置
	if err := config.Save(tempFile); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// 重新加载配置验证
	loadedConfig, err := LoadConfig(tempFile)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	// 验证保存的配置
	if loadedConfig.Server.Port != config.Server.Port {
		t.Errorf("Saved server port mismatch: expected %s, got %s", config.Server.Port, loadedConfig.Server.Port)
	}
	if loadedConfig.Python.ServiceURL != config.Python.ServiceURL {
		t.Errorf("Saved Python service URL mismatch: expected %s, got %s", config.Python.ServiceURL, loadedConfig.Python.ServiceURL)
	}
	if loadedConfig.Database.Type != config.Database.Type {
		t.Errorf("Saved database type mismatch: expected %s, got %s", config.Database.Type, loadedConfig.Database.Type)
	}
	if loadedConfig.Cache.Type != config.Cache.Type {
		t.Errorf("Saved cache type mismatch: expected %s, got %s", config.Cache.Type, loadedConfig.Cache.Type)
	}
}

// 辅助函数
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
