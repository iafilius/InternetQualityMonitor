#!/bin/bash

go build -o iqmon ./src

# curious on platform differences
time ./iqmon -sites ./sites.jsonc -iterations 1 -parallel 1 -log-level debug -http-timeout 45s -stall-timeout 8s -out run_monitor_results.jsonl
