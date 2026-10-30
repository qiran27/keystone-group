#!/bin/sh
set -eu
[ "$#" -eq 3 ] || exit 2
prefix=$1; workers=$2; mode=$3
case "$mode" in all) modes='sync async adaptive' ;; both) modes='async adaptive' ;; *) exit 2 ;; esac
set --
for m in $modes; do set -- "$@" "$prefix-$m.csv" "$prefix-$m-io.csv"; done
tmp=$prefix-comparison.csv.tmp
trap 'rm -f "$tmp"' EXIT
awk -F, -v workers="$workers" -v include_sync="$([ "$mode" = all ] && echo 1 || echo 0)" '
  FNR==1 {
    for(x in h) delete h[x]; for(i=1;i<=NF;i++) h[$i]=i
    perf=("mb_per_sec_median" in h); next
  }
  {
    m=$h["io_mode"]; n=$h["worker_count"]+0; k=m SUBSEP n
    if (n<1 || n>workers || $h["validated"]!=1 || $h["samples"]<1) {bad=1; next}
    signature=$h["workload"] ":" $h["cache_mode"] ":" $h["address_mode"] ":" $h["total_bytes"] ":" $h["samples"]
    cipher=("cipher" in h) ? $h["cipher"] : "aes-ecb-128"
    signature=signature ":" cipher
    if (seen_cipher && result_cipher!=cipher) {bad=1; next}
    seen_cipher=1; result_cipher=cipher
    if ((n in sig) && sig[n]!=signature) {bad=1; next} sig[n]=signature
    if (perf) {if(k in p) bad=1; p[k]=$h["mb_per_sec_median"]+0}
    else {if(k in host) bad=1; host[k]=$h["host_data_operations_median"]+0; logical[k]=$h["logical_requests_median"]+0}
  }
  END {
    for(n=1;n<=workers;n++) {
      a="async-no-extent" SUBSEP n; b="adaptive-extent" SUBSEP n; s="sync-no-extent" SUBSEP n
      if(!(a in p)||!(b in p)||!(a in host)||!(b in host)||p[a]<=0||p[b]<=0||host[a]<=0||logical[a]!=logical[b]) bad=1
      if(include_sync && (!(s in p)||!(s in host)||p[s]<=0||host[s]<=0||logical[s]!=logical[a])) bad=1
    }
    if(bad) exit 2
    print "worker_count,sync_mb_per_sec_median,async_mb_per_sec_median,adaptive_mb_per_sec_median,async_vs_sync_gain_pct,adaptive_vs_sync_gain_pct,adaptive_vs_async_gain_pct,logical_requests_median,sync_host_operations_median,async_host_operations_median,adaptive_host_operations_median,async_vs_sync_io_reduction_pct,adaptive_vs_sync_io_reduction_pct,adaptive_vs_async_io_reduction_pct,cipher"
    for(n=1;n<=workers;n++) {
      a="async-no-extent" SUBSEP n; b="adaptive-extent" SUBSEP n; s="sync-no-extent" SUBSEP n
      printf "%d,%s,%.9f,%.9f,%s,%s,%.6f,%.0f,%s,%.0f,%.0f,%s,%s,%.6f,%s\n",n,
        include_sync?sprintf("%.9f",p[s]):"NA",p[a],p[b],
        include_sync?sprintf("%.6f",100*(p[a]/p[s]-1)):"NA",
        include_sync?sprintf("%.6f",100*(p[b]/p[s]-1)):"NA",100*(p[b]/p[a]-1),logical[a],
        include_sync?sprintf("%.0f",host[s]):"NA",host[a],host[b],
        include_sync?sprintf("%.6f",100*(1-host[a]/host[s])):"NA",
        include_sync?sprintf("%.6f",100*(1-host[b]/host[s])):"NA",100*(1-host[b]/host[a]),result_cipher
    }
  }
' "$@" > "$tmp"
mv "$tmp" "$prefix-comparison.csv"
