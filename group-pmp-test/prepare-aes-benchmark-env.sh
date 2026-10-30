#!/bin/sh
set -eu

# keystone-worker-cpufreq-v2
helper_version=2

action=${1:-apply}
allow_unfixed=${GROUP_PMP_AES_ALLOW_UNFIXED_FREQUENCY:-0}
state_file=${GROUP_PMP_CPU_FREQ_STATE:-/tmp/group-pmp-worker-cpufreq.state}
cpufreq_root=${GROUP_PMP_CPUFREQ_ROOT:-/sys/devices/system/cpu/cpufreq}
verbose=${GROUP_PMP_AES_ENV_VERBOSE:-0}

fail()
{
  echo "[AES-ENV][ERROR] $*" >&2
  exit 1
}

is_worker_policy()
{
  related=$1
  for cpu in $related; do
    case "$cpu" in
      1|2|3) return 0 ;;
    esac
  done
  return 1
}

read_setting()
{
  path=$1
  fallback=${2:-}
  value=$(cat "$path" 2>/dev/null || true)
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
  else
    printf '%s\n' "$fallback"
  fi
}

write_setting()
{
  path=$1
  value=$2
  if [ -w "$path" ]; then
    printf '%s\n' "$value" > "$path"
    return 0
  fi
  [ "$allow_unfixed" = 1 ] && return 0
  fail "$path is not writable"
}

apply_policy()
{
  policy=$1
  max=$(read_setting "$policy/cpuinfo_max_freq")
  [ -n "$max" ] || max=$(read_setting "$policy/scaling_max_freq")
  [ -n "$max" ] || fail "cannot determine maximum frequency for $policy"

  write_setting "$policy/scaling_max_freq" "$max"
  write_setting "$policy/scaling_min_freq" "$max"
  write_setting "$policy/scaling_governor" performance

  governor=$(read_setting "$policy/scaling_governor" unknown)
  minimum=$(read_setting "$policy/scaling_min_freq" unknown)
  maximum=$(read_setting "$policy/scaling_max_freq" unknown)
  if [ "$allow_unfixed" != 1 ] &&
     { [ "$governor" != performance ] ||
       [ "$minimum" != "$max" ] || [ "$maximum" != "$max" ]; }; then
    fail "$policy is not locked: governor=$governor min=$minimum max=$maximum target=$max"
  fi
  if [ "$verbose" = 1 ]; then
    echo "[AES-ENV] policy=$(basename "$policy") governor=$governor target_khz=$max"
  fi
  return 0
}

restore_policy()
{
  policy=$1
  governor=$2
  minimum=$3
  maximum=$4
  cpu_min=$5

  # Drop the temporary high minimum before restoring the old maximum.
  write_setting "$policy/scaling_min_freq" "$cpu_min"
  write_setting "$policy/scaling_max_freq" "$maximum"
  write_setting "$policy/scaling_min_freq" "$minimum"
  write_setting "$policy/scaling_governor" "$governor"
}

case "$action" in
  apply|verify|restore) ;;
  *) fail "usage: $0 [apply|verify|restore]" ;;
esac

if [ "$action" = restore ]; then
  [ -r "$state_file" ] || fail "frequency state is missing: $state_file"
  restored=0
  while IFS='|' read -r policy governor minimum maximum cpu_min; do
    [ -n "$policy" ] || continue
    [ -d "$policy" ] ||
      fail "cpufreq policy disappeared before restore: $policy"
    restore_policy "$policy" "$governor" "$minimum" "$maximum" "$cpu_min"
    restored=$((restored + 1))
  done < "$state_file"
  rm -f "$state_file"
  echo "[AES-ENV] restored worker CPU frequency policies=$restored helper=v$helper_version"
  exit 0
fi

found=0
locked_frequency=
if [ "$action" = apply ]; then
  [ ! -e "$state_file" ] || fail "frequency state already exists: $state_file"
  : > "$state_file"
fi

for policy in "$cpufreq_root"/policy*; do
  [ -d "$policy" ] || continue
  related=$(read_setting "$policy/related_cpus")
  is_worker_policy "$related" || continue
  found=$((found + 1))

  max=$(read_setting "$policy/cpuinfo_max_freq")
  [ -n "$max" ] || max=$(read_setting "$policy/scaling_max_freq")
  [ -n "$max" ] || fail "cannot determine maximum frequency for $policy"

  if [ "$action" = apply ]; then
    governor=$(read_setting "$policy/scaling_governor")
    minimum=$(read_setting "$policy/scaling_min_freq")
    maximum=$(read_setting "$policy/scaling_max_freq")
    cpu_min=$(read_setting "$policy/cpuinfo_min_freq" "$minimum")
    [ -n "$governor" ] && [ -n "$minimum" ] && [ -n "$maximum" ] &&
      [ -n "$cpu_min" ] || fail "cannot snapshot $policy"
    printf '%s|%s|%s|%s|%s\n' \
      "$policy" "$governor" "$minimum" "$maximum" "$cpu_min" \
      >> "$state_file"
    apply_policy "$policy"
  fi

  governor=$(read_setting "$policy/scaling_governor" unknown)
  minimum=$(read_setting "$policy/scaling_min_freq" unknown)
  maximum=$(read_setting "$policy/scaling_max_freq" unknown)
  if [ "$allow_unfixed" != 1 ] &&
     { [ "$governor" != performance ] ||
       [ "$minimum" != "$max" ] || [ "$maximum" != "$max" ]; }; then
    fail "$policy is not locked: governor=$governor min=$minimum max=$maximum target=$max"
  fi
  if [ -n "$locked_frequency" ] && [ "$locked_frequency" != "$max" ] &&
     [ "$allow_unfixed" != 1 ]; then
    fail "worker CPU policies have different targets: $locked_frequency vs $max"
  fi
  locked_frequency=$max
done

if [ "$found" -eq 0 ]; then
  if [ "$action" = apply ]; then
    rm -f "$state_file"
  fi
  [ "$allow_unfixed" = 1 ] ||
    fail "no cpufreq policy covering worker CPU1-3"
  echo "[AES-ENV] warning: worker CPU frequency is not fixed" >&2
fi

echo "[AES-ENV] worker CPU frequency locked policies=$found target_khz=${locked_frequency:-unknown} helper=v$helper_version"
