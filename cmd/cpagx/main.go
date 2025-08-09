package main

import (
	"fmt"
	"log"
	"os"

	"github.com/TonyP4N/cpagx-go/api"
	"github.com/TonyP4N/cpagx-go/internal/config"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "cpagx",
		Usage: "Cyber-Physical Attack Graph Analysis Tool",
		Commands: []*cli.Command{
			{
				Name:  "analyze",
				Usage: "Analyze PCAP files and generate attack graphs",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "configs/config.json",
						Usage:   "Path to configuration file",
					},
				},
				Action: func(c *cli.Context) error {
					// 加载配置文件
					configPath := c.String("config")
					cfg, err := config.LoadConfig(configPath)
					if err != nil {
						return fmt.Errorf("failed to load config from %s: %w", configPath, err)
					}

					// 显示配置信息
					fmt.Printf("Configuration loaded successfully:\n")
					fmt.Printf("  Server: %s\n", cfg.GetServerAddress())
					fmt.Printf("  Python Service: %s\n", cfg.Python.ServiceURL)
					fmt.Printf("  Database: %s\n", cfg.Database.Type)
					fmt.Printf("  Cache: %s\n", cfg.Cache.Type)
					fmt.Printf("  Environment: %s\n", getEnvironment(cfg))

					// TODO: 实现分析逻辑
					fmt.Println("Analysis functionality will be implemented here...")
					return nil
				},
			},
			{
				Name:  "server",
				Usage: "Start the API server",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "configs/config.json",
						Usage:   "Path to configuration file",
					},
				},
				Action: func(c *cli.Context) error {
					// 加载配置文件
					configPath := c.String("config")
					cfg, err := config.LoadConfig(configPath)
					if err != nil {
						return fmt.Errorf("failed to load config from %s: %w", configPath, err)
					}

					// 显示服务器配置
					fmt.Printf("Starting server on %s\n", cfg.GetServerAddress())
					fmt.Printf("Python service: %s\n", cfg.Python.ServiceURL)

					// 设置 Python 服务 URL 到环境变量，供 API 层读取
					_ = os.Setenv("PYTHON_SERVICE_URL", cfg.Python.ServiceURL)

					// 启动 Gin 服务器
					r := api.NewServer()
					if err := r.Run(cfg.GetServerAddress()); err != nil {
						return fmt.Errorf("failed to start server: %w", err)
					}
					return nil
				},
			},
			{
				Name:  "config",
				Usage: "Configuration management",
				Subcommands: []*cli.Command{
					{
						Name:  "show",
						Usage: "Show current configuration",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "config",
								Aliases: []string{"c"},
								Value:   "configs/config.json",
								Usage:   "Path to configuration file",
							},
						},
						Action: func(c *cli.Context) error {
							configPath := c.String("config")
							cfg, err := config.LoadConfig(configPath)
							if err != nil {
								return fmt.Errorf("failed to load config: %w", err)
							}

							fmt.Printf("Configuration from: %s\n", configPath)
							fmt.Printf("Server: %s:%s\n", cfg.Server.Host, cfg.Server.Port)
							fmt.Printf("Python Service: %s (timeout: %v, retries: %d)\n",
								cfg.Python.ServiceURL, cfg.Python.Timeout, cfg.Python.Retries)
							fmt.Printf("Database: %s://%s:%d/%s\n",
								cfg.Database.Type, cfg.Database.Host, cfg.Database.Port, cfg.Database.Database)
							fmt.Printf("Cache: %s (TTL: %v, max size: %d)\n",
								cfg.Cache.Type, cfg.Cache.TTL, cfg.Cache.MaxSize)
							return nil
						},
					},
					{
						Name:  "save",
						Usage: "Save current configuration to file",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "output",
								Aliases:  []string{"o"},
								Required: true,
								Usage:    "Output file path",
							},
						},
						Action: func(c *cli.Context) error {
							configPath := c.String("config")
							outputPath := c.String("output")

							// 加载当前配置
							cfg, err := config.LoadConfig(configPath)
							if err != nil {
								return fmt.Errorf("failed to load config: %w", err)
							}

							// 保存到新文件
							if err := cfg.Save(outputPath); err != nil {
								return fmt.Errorf("failed to save config: %w", err)
							}

							fmt.Printf("Configuration saved to: %s\n", outputPath)
							return nil
						},
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// getEnvironment 根据配置判断环境类型
func getEnvironment(cfg *config.Config) string {
	if cfg.IsDevelopment() {
		return "development"
	}
	if cfg.IsProduction() {
		return "production"
	}
	return "unknown"
}
