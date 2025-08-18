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
					fmt.Printf("Loaded configuration: %s\n", cfg.String())

					// TODO: 实现分析逻辑

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

					// 设置 Python 服务 URL 到环境变量，供 API 层读取
					_ = os.Setenv("PYTHON_SERVICE_URL", cfg.Python.ServiceURL)

					// 启动 Gin 服务器
					r := api.NewServer(cfg)
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

							fmt.Printf("Current configuration:\n%s\n", cfg.String())
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
