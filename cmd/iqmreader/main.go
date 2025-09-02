package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/iafilius/InternetQualityMonitor/src/analysis"
	"github.com/iafilius/InternetQualityMonitor/src/monitor"
)

func main() {
	var file string
	var max int
	var situation string
	flag.StringVar(&file, "file", "monitor_results.jsonl", "Path to monitor_results.jsonl")
	flag.IntVar(&max, "n", 5000, "Max batches to load")
	flag.StringVar(&situation, "situation", "", "Optional situation filter (exact match)")
	flag.Parse()
	sums, err := analysis.AnalyzeRecentResultsFull(file, monitor.SchemaVersion, max, situation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	counts := map[string]int{}
	for _, s := range sums {
		k := s.Situation
		if k == "" {
			k = "(none)"
		}
		counts[k]++
	}
	fmt.Printf("Total batches: %d\n", len(sums))
	for k, v := range counts {
		fmt.Printf("%s: %d\n", k, v)
	}
}
