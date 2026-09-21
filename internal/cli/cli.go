package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"gfw-x/internal/api"
	"gfw-x/internal/bench"
	"gfw-x/internal/config"
	"gfw-x/internal/detect"
	"gfw-x/internal/dpi"
	"gfw-x/internal/export"
	"gfw-x/internal/gateway"
	"gfw-x/internal/logging"
	"gfw-x/internal/metrics"
	"gfw-x/internal/nfq"
	"gfw-x/internal/pipeline"
	"gfw-x/internal/rules"
	"gfw-x/internal/version"
)

// Run dispatches the CLI subcommands.
func Run(args []string) int {
	if len(args) < 1 {
		return cmdRun([]string{})
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "validate":
		return cmdValidate(args[1:])
	case "bench":
		return cmdBench(args[1:])
	case "export":
		return cmdExport(args[1:])
	case "version":
		fmt.Println(version.Info())
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "gfwx: unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Print(`GFW X - The firewall evolves. So does the gateway.

Usage:
  gfwx run [flags]            Run the gateway + web dashboard
  gfwx validate [flags]       Validate config + rules without starting the gateway
  gfwx bench [flags]          Run a performance benchmark
  gfwx export [flags]         Export rules / logs / diagnostic bundle
  gfwx version                Print version

Run flags:
  --config path   Config file (YAML or JSON) [default configs/config.yaml]
  --mode m        Start mode: bypass | block | custom
  --gen-rate n    Synthetic traffic generator rate (events/sec)
  --no-gen        Disable the synthetic traffic generator
  --pcap path     Replay a classic .pcap file as the traffic input (takes
                  precedence over the generator)
  --pcap-rate n   Cap replay emissions/sec (0 = no pacing)
  --pprof         Enable /debug/pprof

Validate flags:
  --config path   Config file to validate
  --rules path    Rules file to validate (yaml/json/txt)

Bench flags:
  --flows n       Number of flows to benchmark [default 20000]
  --workers n     Worker pool size [default 4]

Export flags:
  --config path   Config file
  --rules path    Rules file
  --dir path      Output directory [default ./export]
  --zip           Pack into gfwx-export.zip
  --redact        Privacy-mask IPs
`)
}

// loadRules loads a rule set from a file, or the named preset, or a bootstrap set.
func loadRules(path string, presetName string) (*rules.RuleRepo, error) {
	repo := rules.NewRepo()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			// If the file is missing but it's a default, fall back to preset.
			return nil, fmt.Errorf("load rules %s: %w", path, err)
		}
		rs, err := rules.ParseBytes(data, path)
		if err != nil {
			return nil, err
		}
		repo.Replace(rs)
		return repo, nil
	}
	if presetName != "" {
		if p, ok := rules.PresetBy(presetName); ok {
			repo.Replace(p.Rules)
			return repo, nil
		}
	}
	// developer preset is a sensible out-of-the-box start.
	p, _ := rules.PresetBy("developer")
	repo.Replace(p.Rules)
	return repo, nil
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "config file")
	mode := fs.String("mode", "", "start mode override")
	genRate := fs.Int("gen-rate", 200, "generator events/sec")
	noGen := fs.Bool("no-gen", false, "disable generator")
	pcapPath := fs.String("pcap", "", "replay a classic .pcap file as real traffic input")
	pcapRate := fs.Int("pcap-rate", 0, "cap replay emissions/sec (0 = no pacing)")
	pprofOn := fs.Bool("pprof", false, "enable pprof")
	_ = fs.Parse(args)

	cfg := config.DefaultConfig()
	if fileExists(*cfgPath) {
		loaded, err := config.Load(*cfgPath)
		if err != nil {
			log.Printf("warn: %v (using defaults)", err)
		} else {
			cfg = loaded
		}
	}
	if *mode != "" {
		m, err := config.ParseMode(*mode)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		cfg.Default.Mode = m
	}

	if *pprofOn {
		go func() { _ = http.ListenAndServe("127.0.0.1:6060", nil) }()
		log.Printf("pprof available at http://127.0.0.1:6060/debug/pprof")
	}

	// Logging pipeline.
	var storage logging.Storage
	switch strings.ToLower(cfg.Logging.Format) {
	case "ring":
		storage = logging.RingStorage{}
	case "jsonl", "csv":
		f, err := logging.NewFileStorage(cfg.Logging.Dir, cfg.Logging.Format, cfg.Logging.MaxBytes, cfg.Logging.MaxFiles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logging setup: %v\n", err)
			return 1
		}
		storage = f
	default:
		storage = logging.RingStorage{}
	}
	pipe := logging.NewPipeline(storage, cfg.Logging.QueueSize, cfg.Logging.Redact, cfg.Logging.SampleRatio)

	// Rule repo.
	repo, err := loadRules(cfg.RulesFile, defaultPresetFor(cfg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	// Keep both repositories available for later mode switches.
	var customRepo *rules.RuleRepo
	if cfg.CustomFile != "" {
		customRepo, err = loadRules(cfg.CustomFile, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "load custom rules: %v\n", err)
			return 1
		}
	}

	m := metrics.New(cfg.Logging.MaxRing)
	det := detect.NewEngine(cfg.Detect.Enabled, cfg.Detect.Threshold, cfg.Detect.AutoAction == "reject" || cfg.Detect.AutoAction == "drop")
	dpiEng := dpi.NewEngine(true, cfg.Default.DPI)

	gw := gateway.New(cfg, repo, m, pipe, det, dpiEng)
	if customRepo != nil {
		gw.SetCustomRepo(customRepo)
	}
	gw.Start()

	var gen *gateway.Generator
	var rpl *gateway.Replay
	var nfs *nfqSession
	switch cfg.Dataplane.Mode {
	case config.DataplaneNFQueue:
		session, err := startNFQueue(gw, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nfqueue data plane: %v\n", err)
			gw.Stop()
			pipe.Close()
			return 1
		}
		nfs = session
	case config.DataplanePCAP:
		if *pcapPath != "" {
			rpl = gateway.NewReplay(gw, *pcapPath, *pcapRate)
			if err := rpl.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "pcap replay: %v\n", err)
				gw.Stop()
				pipe.Close()
				return 1
			}
		} else if !*noGen {
			gen = gateway.NewGenerator(gw, *genRate)
			gen.Start()
		}
	}
	defer func() {
		if gen != nil {
			gen.Stop()
		}
		if rpl != nil {
			rpl.Stop()
		}
		if nfs != nil {
			nfs.stop()
		}
		gw.Stop()
		pipe.Close()
	}()

	// API server.
	srv := api.New(gw, cfg)
	go func() {
		if err := srv.Listen(); err != nil {
			log.Printf("dashboard stopped: %v", err)
		}
	}()
	log.Printf("GFW X %s started (mode=%s dataplane=%s)", version.Info(), gw.Mode(), cfg.Dataplane.Mode)
	if nfs != nil {
		log.Printf("nfqueue data plane active: queue %d (fail_mode=%s)", cfg.Dataplane.NFQueue.QueueNum, cfg.Dataplane.NFQueue.FailMode)
	}
	if gen != nil {
		log.Printf("synthetic traffic generator active at %d ev/s (disable with --no-gen)", *genRate)
	}
	if rpl != nil {
		log.Printf("pcap replay active: %s", *pcapPath)
	}

	waitForSignal()
	log.Printf("GFW X shutting down")
	return 0
}

func defaultPresetFor(cfg *config.Config) string {
	return ""
}

// nfqSession owns the NFQUEUE data-plane runner lifecycle.
type nfqSession struct {
	runner *pipeline.Runner
	done   chan struct{}
}

// startNFQueue opens the NFQUEUE source and sink and drives them through the
// unified pipeline on a fixed worker pool. The verdict sink mirrors queue
// overflows into the gateway's Prometheus counters. The returned session must
// be stopped to free the queue cleanly.
func startNFQueue(gw *gateway.Gateway, cfg *config.Config) (*nfqSession, error) {
	src, err := nfq.NewSource(cfg.Dataplane.NFQueue)
	if err != nil {
		return nil, err
	}
	sink, err := nfq.NewSink(src, cfg.Dataplane.NFQueue.FailMode, func(v int64) { gw.SetNFOverflows(v) })
	if err != nil {
		src.Stop()
		return nil, err
	}
	proc := pipeline.Processor(func(ctx context.Context, p *pipeline.Packet) (pipeline.Verdict, error) {
		return gw.HandlePacket(ctx, p), nil
	})
	workers := cfg.Dataplane.NFQueue.MaxWorkers
	if workers < 1 {
		workers = 1
	}
	runner := pipeline.NewRunner(src, proc, sink, workers)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := runner.Run(); err != nil && !errors.Is(err, pipeline.ErrStopped) {
			log.Printf("nfqueue runner exited: %v", err)
		}
	}()
	return &nfqSession{runner: runner, done: done}, nil
}

// stop cancels the runner and waits for the source/sink to be released.
func (s *nfqSession) stop() {
	if s.runner != nil {
		s.runner.Stop()
	}
	if s.done != nil {
		<-s.done
	}
}

func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "config file")
	rulesPath := fs.String("rules", "", "rules file")
	_ = fs.Parse(args)

	if fileExists(*cfgPath) {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
			return 1
		}
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
			return 1
		}
		fmt.Println("config OK")
	} else {
		fmt.Println("config: no file (skipped)")
	}

	if *rulesPath != "" {
		data, err := os.ReadFile(*rulesPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules: %v\n", err)
			return 1
		}
		rs, err := rules.ParseBytes(data, *rulesPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules invalid: %v\n", err)
			return 1
		}
		if _, err := rules.MarshalYAML(rs); err != nil {
			fmt.Fprintf(os.Stderr, "rules re-serialize failed: %v\n", err)
			return 1
		}
		fmt.Printf("rules OK (%d rules, %d conflicts)\n", len(rs), len(rules.FindConflicts(rs)))
	}
	return 0
}

func cmdBench(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	flows := fs.Int("flows", 20000, "flows")
	workers := fs.Int("workers", 4, "workers")
	_ = fs.Parse(args)
	rep, err := bench.Run(*flows, *workers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: %v\n", err)
		return 1
	}
	fmt.Println(rep.String())
	return 0
}

func cmdExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/config.yaml", "config file")
	rulesPath := fs.String("rules", "", "rules file")
	dir := fs.String("dir", "./export", "output dir")
	zipOut := fs.Bool("zip", false, "pack into gfwx-export.zip")
	redact := fs.Bool("redact", false, "privacy-mask IPs")
	_ = fs.Parse(args)

	cfg := config.DefaultConfig()
	if fileExists(*cfgPath) {
		if c, err := config.Load(*cfgPath); err == nil {
			cfg = c
		}
	}
	repo, err := loadRules(*rulesPath, defaultPresetFor(cfg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	b := &export.Bundle{
		Config: cfg, Rules: repo.All(),
		Metrics: metrics.New(8), Format: cfg.Logging.Format,
	}
	// If logs on disk exist, expose them too is out of scope here; events come
	// from an in-memory registry in export for simplicity.
	out, err := export.Run(b, export.Options{ZIP: *zipOut, Redact: *redact, OutDir: *dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "export: %v\n", err)
		return 1
	}
	fmt.Printf("exported to %s\n", filepath.Clean(out))
	return 0
}

func waitForSignal() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
