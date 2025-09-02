#!/bin/bash

# Find stalled in a specific Situation, on CLI

set -euo pipefail
ls -lah monitor_results.jsonl || echo "NOFILE"
if [ -f monitor_results.jsonl ]; then
  echo "--- counts for situation Home_CorporateLaptop_CorpProxy_SequencedTest ---"
  jq -c 'select(.meta!=null and .site_result!=null) | select(.meta.situation=="Home_CorporateLaptop_CorpProxy_SequencedTest") | .site_result.transfer_stalled' monitor_results.jsonl | awk '{if($0=="true") c++} END{print "transfer_stalled_true:", (c+0)}'
  jq -c 'select(.meta!=null and .site_result!=null) | select(.meta.situation=="Home_CorporateLaptop_CorpProxy_SequencedTest") | .site_result.http_error' monitor_results.jsonl | grep -i stall | sort | uniq -c || true
  echo "--- total lines in situation ---"
  jq -c 'select(.meta!=null and .site_result!=null) | select(.meta.situation=="Home_CorporateLaptop_CorpProxy_SequencedTest")' monitor_results.jsonl | wc -l
fi
#exit
# 
set -euo pipefail
if [ -f monitor_results.jsonl ]; then
  echo "FOUND monitor_results.jsonl";
  echo "File size:"; /bin/ls -lh monitor_results.jsonl;
  echo "--- total lines for situation ---";
  jq -c 'select(.meta!=null and .site_result!=null) | select(.meta.situation=="Home_CorporateLaptop_CorpProxy_SequencedTest")' monitor_results.jsonl | wc -l;
  echo "--- transfer_stalled=true count ---";
  jq -r 'select(.meta!=null and .site_result!=null) | select(.meta.situation=="Home_CorporateLaptop_CorpProxy_SequencedTest") | .site_result.transfer_stalled' monitor_results.jsonl | awk '$0=="true"{c++} END{print c+0}';
  echo "--- any http_error containing stall ---";
  jq -r 'select(.meta!=null and .site_result!=null) | select(.meta.situation=="Home_CorporateLaptop_CorpProxy_SequencedTest") | .site_result.http_error' monitor_results.jsonl | grep -i stall | sort | uniq -c || true;
  echo "--- sample stalled lines (first 3) ---";
  jq -c 'select(.meta!=null and .site_result!=null) | select(.meta.situation=="Home_CorporateLaptop_CorpProxy_SequencedTest" and .site_result.transfer_stalled==true) | {t:.meta.start_time, site:.meta.site, err:.site_result.http_error, stall_ms:.site_result.stall_elapsed_ms}' monitor_results.jsonl | head -n 3 || true;
else
  echo "monitor_results.jsonl not found in workspace root";
fi