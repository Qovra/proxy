package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Qovra/core/internal/handler"
	"github.com/Qovra/core/internal/metrics"
	"github.com/Qovra/core/internal/proxy"

	_ "github.com/Qovra/core/internal/handler"
)

var Version = "0.1.0"

func main() {
	configFlag := flag.String("config", "", "Config file path or JSON string")
	debugFlag := flag.Bool("d", false, "Enable debug logging")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println(Version)
		os.Exit(0)
	}

	if *configFlag == "" {
		log.Fatal("error: -config is required")
	}

	cfg, isFile, err := loadConfig(*configFlag)
	if err != nil {
		log.Fatalf("error: failed to load config: %v", err)
	}

	if *debugFlag {
		log.Println("[main] debug mode enabled")
	}

	if cfg.Listen == "" {
		cfg.Listen = getEnv("PROXY_LISTEN", ":5520")
	}

	chain, err := handler.BuildChain(cfg.Handlers)
	if err != nil {
		log.Fatalf("error: failed to build handler chain: %v", err)
	}

	p := proxy.New(cfg.Listen, chain)
	p.SetSessionTimeout(cfg.SessionTimeout)

	// Start metrics server if configured
	if cfg.MetricsListen != "" {
		m := metrics.New(cfg.MetricsListen, p)
		m.Start()
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				if !isFile {
					log.Println("[main] SIGHUP ignored (config is inline JSON)")
					continue
				}
				newCfg, _, err := loadConfig(*configFlag)
				if err != nil {
					log.Printf("[main] reload failed: %v", err)
					continue
				}
				newChain, err := handler.BuildChain(newCfg.Handlers)
				if err != nil {
					log.Printf("[main] reload failed: %v", err)
					continue
				}
				p.ReloadChain(newChain)
				p.SetSessionTimeout(newCfg.SessionTimeout)
				log.Printf("[main] config reloaded")
			case syscall.SIGINT, syscall.SIGTERM:
				log.Println("[main] shutting down...")
				p.Stop()
				os.Exit(0)
			}
		}
	}()

	if err := p.Run(); err != nil {
		log.Fatalf("error: proxy failed: %v", err)
	}
}

func loadConfig(configFlag string) (*proxy.Config, bool, error) {
	if strings.HasPrefix(configFlag, "{") {
		cfg, err := proxy.ParseConfig([]byte(configFlag))
		return cfg, false, err
	}
	cfg, err := proxy.LoadConfig(configFlag)
	return cfg, true, err
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
