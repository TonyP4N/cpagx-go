package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// VersionConfig 版本配置
type VersionConfig struct {
	Port        int    `json:"port"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// VersionsConfig 版本管理配置
type VersionsConfig struct {
	Versions       map[string]VersionConfig `json:"versions"`
	DefaultVersion string                   `json:"default_version"`
}

// Config 应用配置结构
type Config struct {
	Server   ServerConfig   `json:"server"`
	Python   PythonConfig   `json:"python"`
	Database DatabaseConfig `json:"database"`
	Cache    CacheConfig    `json:"cache"`
	Versions VersionsConfig `json:"versions"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port         string        `json:"port"`
	Host         string        `json:"host"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
}

// PythonConfig Python微服务配置
type PythonConfig struct {
	ServiceURL string        `json:"service_url"`
	Timeout    time.Duration `json:"timeout"`
	Retries    int           `json:"retries"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Type     string `json:"type"` // "redis", "postgres", "sqlite"
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// CacheConfig 缓存配置
type CacheConfig struct {
	Type    string        `json:"type"` // "memory", "redis"
	TTL     time.Duration `json:"ttl"`
	MaxSize int           `json:"max_size"`
}

// Duration 自定义时间类型，支持JSON字符串解析
type Duration time.Duration

// UnmarshalJSON 从JSON字符串解析时间
func (d *Duration) UnmarshalJSON(data []byte) error {
	// 移除引号
	str := string(data)
	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		str = str[1 : len(str)-1]
	}

	duration, err := time.ParseDuration(str)
	if err != nil {
		return fmt.Errorf("invalid duration format: %s", str)
	}

	*d = Duration(duration)
	return nil
}

// MarshalJSON 将时间序列化为JSON字符串
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Duration 转换为time.Duration
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// ServerConfigWithDuration 支持时间字符串的服务器配置
type ServerConfigWithDuration struct {
	Port         string   `json:"port"`
	Host         string   `json:"host"`
	ReadTimeout  Duration `json:"read_timeout"`
	WriteTimeout Duration `json:"write_timeout"`
}

// PythonConfigWithDuration 支持时间字符串的Python配置
type PythonConfigWithDuration struct {
	ServiceURL string   `json:"service_url"`
	Timeout    Duration `json:"timeout"`
	Retries    int      `json:"retries"`
}

// CacheConfigWithDuration 支持时间字符串的缓存配置
type CacheConfigWithDuration struct {
	Type    string   `json:"type"`
	TTL     Duration `json:"ttl"`
	MaxSize int      `json:"max_size"`
}

// ConfigWithDuration 支持时间字符串的完整配置
type ConfigWithDuration struct {
	Server   ServerConfigWithDuration `json:"server"`
	Python   PythonConfigWithDuration `json:"python"`
	Database DatabaseConfig           `json:"database"`
	Cache    CacheConfigWithDuration  `json:"cache"`
	Versions VersionsConfig           `json:"versions"`
}

// LoadVersionsConfig 从JSON文件加载版本配置
func LoadVersionsConfig(versionsPath string) (*VersionsConfig, error) {
	file, err := os.Open(versionsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open versions config file: %w", err)
	}
	defer file.Close()

	versionsConfig := &VersionsConfig{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(versionsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode versions config file: %w", err)
	}

	return versionsConfig, nil
}

// LoadConfig 从JSON文件加载配置
func LoadConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// 先解析为支持时间字符串的配置
	configWithDuration := &ConfigWithDuration{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(configWithDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	// 转换为标准配置
	config := &Config{
		Server: ServerConfig{
			Port:         configWithDuration.Server.Port,
			Host:         configWithDuration.Server.Host,
			ReadTimeout:  configWithDuration.Server.ReadTimeout.Duration(),
			WriteTimeout: configWithDuration.Server.WriteTimeout.Duration(),
		},
		Python: PythonConfig{
			ServiceURL: configWithDuration.Python.ServiceURL,
			Timeout:    configWithDuration.Python.Timeout.Duration(),
			Retries:    configWithDuration.Python.Retries,
		},
		Database: configWithDuration.Database,
		Cache: CacheConfig{
			Type:    configWithDuration.Cache.Type,
			TTL:     configWithDuration.Cache.TTL.Duration(),
			MaxSize: configWithDuration.Cache.MaxSize,
		},
		Versions: configWithDuration.Versions,
	}

	// 验证配置
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// Save 保存配置到JSON文件
func (c *Config) Save(filePath string) error {
	// 创建临时配置结构用于保存，使用Duration类型处理时间
	tempConfig := struct {
		Server struct {
			Port         string   `json:"port"`
			Host         string   `json:"host"`
			ReadTimeout  Duration `json:"read_timeout"`
			WriteTimeout Duration `json:"write_timeout"`
		} `json:"server"`
		Python struct {
			ServiceURL string   `json:"service_url"`
			Timeout    Duration `json:"timeout"`
			Retries    int      `json:"retries"`
		} `json:"python"`
		Database DatabaseConfig `json:"database"`
		Cache    struct {
			Type    string   `json:"type"`
			TTL     Duration `json:"ttl"`
			MaxSize int      `json:"max_size"`
		} `json:"cache"`
	}{
		Server: struct {
			Port         string   `json:"port"`
			Host         string   `json:"host"`
			ReadTimeout  Duration `json:"read_timeout"`
			WriteTimeout Duration `json:"write_timeout"`
		}{
			Port:         c.Server.Port,
			Host:         c.Server.Host,
			ReadTimeout:  Duration(c.Server.ReadTimeout),
			WriteTimeout: Duration(c.Server.WriteTimeout),
		},
		Python: struct {
			ServiceURL string   `json:"service_url"`
			Timeout    Duration `json:"timeout"`
			Retries    int      `json:"retries"`
		}{
			ServiceURL: c.Python.ServiceURL,
			Timeout:    Duration(c.Python.Timeout),
			Retries:    c.Python.Retries,
		},
		Database: c.Database,
		Cache: struct {
			Type    string   `json:"type"`
			TTL     Duration `json:"ttl"`
			MaxSize int      `json:"max_size"`
		}{
			Type:    c.Cache.Type,
			TTL:     Duration(c.Cache.TTL),
			MaxSize: c.Cache.MaxSize,
		},
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(tempConfig); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// GetServerAddress 获取服务器地址
func (c *Config) GetServerAddress() string {
	return c.Server.Host + ":" + c.Server.Port
}

// IsDevelopment 检查是否为开发环境
func (c *Config) IsDevelopment() bool {
	return c.Server.Host == "localhost" || c.Server.Host == "127.0.0.1"
}

// IsProduction 检查是否为生产环境
func (c *Config) IsProduction() bool {
	return c.Server.Host == "0.0.0.0" && c.Database.Type == "redis"
}

// validateConfig 验证配置的有效性
func validateConfig(config *Config) error {
	var errors []string

	// 验证服务器端口
	if config.Server.Port == "" {
		errors = append(errors, "server port cannot be empty")
	} else if port, err := strconv.Atoi(config.Server.Port); err != nil || port <= 0 || port > 65535 {
		errors = append(errors, "server port must be a valid port number (1-65535)")
	}

	// 验证服务器主机
	if config.Server.Host == "" {
		errors = append(errors, "server host cannot be empty")
	}

	// 验证Python服务URL
	if config.Python.ServiceURL == "" {
		errors = append(errors, "python service URL cannot be empty")
	} else if !strings.HasPrefix(config.Python.ServiceURL, "http://") && !strings.HasPrefix(config.Python.ServiceURL, "https://") {
		errors = append(errors, "python service URL must start with http:// or https://")
	}

	// 验证Python重试次数
	if config.Python.Retries < 0 || config.Python.Retries > 10 {
		errors = append(errors, "python retries must be between 0 and 10")
	}

	// 验证数据库类型
	validDBTypes := map[string]bool{"sqlite": true, "redis": true, "postgres": true}
	if !validDBTypes[config.Database.Type] {
		errors = append(errors, fmt.Sprintf("invalid database type: %s (valid types: sqlite, redis, postgres)", config.Database.Type))
	}

	// 验证数据库端口（SQLite可以使用0端口）
	if config.Database.Type != "sqlite" && (config.Database.Port <= 0 || config.Database.Port > 65535) {
		errors = append(errors, "database port must be a valid port number (1-65535)")
	}

	// 验证缓存类型
	validCacheTypes := map[string]bool{"memory": true, "redis": true}
	if !validCacheTypes[config.Cache.Type] {
		errors = append(errors, fmt.Sprintf("invalid cache type: %s (valid types: memory, redis)", config.Cache.Type))
	}

	// 验证缓存大小
	if config.Cache.MaxSize <= 0 {
		errors = append(errors, "cache max size must be greater than 0")
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// String 返回配置的字符串表示
func (c *Config) String() string {
	return fmt.Sprintf("Server: %s:%s, Python: %s, DB: %s, Cache: %s",
		c.Server.Host, c.Server.Port, c.Python.ServiceURL, c.Database.Type, c.Cache.Type)
}
