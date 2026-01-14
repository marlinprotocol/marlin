#!/run/current-system/sw/bin/bash

job_exists() {
  local job_id="$1"
  local job_file="/var/run/oyster-jobs/$job_id"
  if [ -f "$job_file" ]; then
    return 0
  else
    return 1
  fi
}

free_bandwidth_usage() {
  local bandwidth="$1"
  local lock_file="/var/lock/rate_limiter.lock"
  local usage_file="/var/run/bandwidth_usage.txt"

  local lock_fd
  exec {lock_fd}> "$lock_file" || return 1
  flock -x "$lock_fd" || return 1

  local current_usage
  current_usage=$(cat "$usage_file" 2>/dev/null)

  local new_usage=$((current_usage - bandwidth))
  [ "$new_usage" -lt 0 ] && new_usage=0

  echo "$new_usage" | sudo tee "$usage_file" > /dev/null

  exec {lock_fd}>&-
}

remove_job() {
  local job_id="$1"
  local job_file="/var/run/oyster-jobs/$job_id"

  sudo rm "$job_file"
}

remove_tc_rules() {
  local private_ip="$1"

  local dev
  dev="ens5"  # TODO: get device name

  # Convert private_ip to hex decimal string for filter handle
  private_ip_hex=$(echo "$private_ip" | awk -F. '{printf "%02x%02x%02x%02x\n", $1, $2, $3, $4}')

  filter=$(sudo tc filter show dev "$dev" parent 1: 2>/dev/null | grep -B1 "$private_ip_hex" | head -n1)
  if [ -z "$filter" ]; then
    return 0
  fi

  filter_handle=$(echo "$filter" | awk -F'fh ' '{print $2}' | awk '{print $1}')
  classid=$(echo "$filter" | awk -F'flowid ' '{print $2}' | awk '{print $1}')

  sudo tc filter del dev "$dev" parent 1: protocol ip pref 1 handle "$filter_handle" u32
  sudo tc class del dev "$dev" parent 1: classid "$classid"

}
