// loadtest requires an explicit isolated configuration; it has no target defaults.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"cheesetrap/internal/ingestion"
	"cheesetrap/internal/loadtest"
)

func execute(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("loadtest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "isolated configuration file")
	scenariosPath := flags.String("scenarios", "tests/performance/scenarios.json", "scenario document")
	name := flags.String("scenario", "", "explicit scenario name")
	reportPath := flags.String("report", "", "new private JSON report file; stdout when omitted")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" || *name == "" {
		return errors.New("usage: loadtest -config FILE -scenario NAME [-scenarios FILE] [-report NEW_FILE]")
	}
	read := func(path string, dest any) error {
		f, e := os.Open(path)
		if e != nil {
			return errors.New("input_file_unreadable")
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, 65537))
		if e != nil || len(b) > 65536 {
			return errors.New("input_file_limit")
		}
		return loadtest.Decode(b, dest)
	}
	var c loadtest.Config
	if e := read(*configPath, &c); e != nil {
		return e
	}
	var doc struct {
		SchemaVersion int                 `json:"schema_version"`
		Notes         []string            `json:"notes"`
		Scenarios     []loadtest.Scenario `json:"scenarios"`
	}
	if e := read(*scenariosPath, &doc); e != nil {
		return e
	}
	if doc.SchemaVersion != 1 {
		return errors.New("scenario_schema_invalid")
	}
	var selected *loadtest.Scenario
	for i := range doc.Scenarios {
		if doc.Scenarios[i].Name == *name {
			if selected != nil {
				return errors.New("duplicate_scenario")
			}
			selected = &doc.Scenarios[i]
		}
	}
	if selected == nil {
		return errors.New("scenario_not_found")
	}
	if e := c.Validate(*selected); e != nil {
		return e
	}
	sources, e := ingestion.LoadSources(c.CollectorLogDir, c.CollectorSourcesFile)
	if e != nil {
		return errors.New("verified_collector_sources_required")
	}
	services := map[string]bool{}
	for _, s := range sources {
		if !s.IsTest {
			return errors.New("all_collector_sources_must_be_test")
		}
		for _, ep := range s.Endpoints {
			services[ep.Service] = true
		}
	}
	if selected.SSHPerSecond > 0 && !services["ssh"] || selected.HTTPPerSecond > 0 && !services["http"] || selected.HTTPSPerSecond > 0 && !services["https"] {
		return errors.New("matching_test_sources_required")
	}
	// Create the output before producing traffic; refuse to overwrite evidence.
	if *reportPath != "" {
		f, e := os.OpenFile(*reportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errors.New("new_report_file_required")
		}
		defer f.Close()
		out = f
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	report, e := loadtest.Run(ctx, c, *selected)
	if e != nil {
		return e
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if e = encoder.Encode(report); e != nil {
		return errors.New("report_write_failed")
	}
	if report.Cancelled {
		return errors.New("run_cancelled_report_partial")
	}
	if report.SSH.Failed+report.HTTP.Failed+report.HTTPS.Failed+report.SSH.Dropped+report.HTTP.Dropped+report.HTTPS.Dropped > 0 {
		return errors.New("input_failures_or_drops_reported")
	}
	return nil
}
func main() {
	if e := execute(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
