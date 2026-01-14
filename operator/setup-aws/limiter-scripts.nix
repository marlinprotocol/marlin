{
  pkgs,
  ...
}:
let
  common_rl = pkgs.writeText "common_rl.sh" ''
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

  '';

  add_rl = pkgs.writeShellScriptBin "add_rl" ''
    if [ "$#" -ne 4 ]; then
      echo "Usage: $0 <job_id> <private_ip> <bandwidth> <instance_bandwidth>"
      exit 1
    fi

    source ${common_rl}

    JOB_ID="$1"
    PRIVATE_IP="$2"
    BANDWIDTH="$3"
    INSTANCE_BANDWIDTH="$4"

    check_and_update_bandwidth() {
      local bandwidth="$1"
      local instance_bandwidth="$2"
      local bandwidth_usage_file="/var/run/bandwidth_usage.txt"
      local lock_file="/var/lock/rate_limiter.lock"

      local lock_fd
      exec {lock_fd}> "$lock_file" || return 1
      flock -x "$lock_fd" || return 1

      if [ ! -f "$bandwidth_usage_file" ]; then
        sudo touch "$bandwidth_usage_file"
        echo "0" | sudo tee "$bandwidth_usage_file" > /dev/null
        sudo chmod 644 "$bandwidth_usage_file"
      fi

      local current_usage
      current_usage=$(cat "$bandwidth_usage_file" 2>/dev/null)
      local new_usage=$((current_usage + bandwidth))

      if [ "$new_usage" -gt "$instance_bandwidth" ]; then
        echo "Cannot allocate $bandwidth bps. Current usage: $current_usage bps, Instance limit: $instance_bandwidth bps" >&2
        exec {lock_fd}>&-
        return 1
      fi

      echo "$new_usage" | sudo tee "$bandwidth_usage_file" > /dev/null
      exec {lock_fd}>&-
      return 0
    }

    add_tc_rules() {
      local private_ip="$1"
      local bandwidth="$2"

      # TODO: get device name
      dev="ens5"

      # Ensure HTB root qdisc with handle 1: exists
      if ! tc qdisc show dev "$dev" | grep -q 'htb 1: root'; then
        sudo tc qdisc add dev "$dev" root handle 1: htb
      fi

      # Try adding a random class id directly; on failure retry to avoid races
      local class_id
      local attempt max_attempts=1000
      for attempt in $(seq 1 $max_attempts); do
        # combine RANDOMs to get a wider range, ensure between 1 and 9999
        class_id=$(( (RANDOM % 9999) + 1 ))
        if sudo tc class add dev "$dev" parent 1: classid 1:"$class_id" htb rate "$bandwidth" burst 4000m 2>/dev/null; then
            break
        fi
      done

      if [ "$attempt" -eq "$max_attempts" ]; then
        echo "Failed to add tc class after $max_attempts attempts" >&2
        return 1
      fi

      # Add filter matching source IP to this class if not present
      sudo tc filter add dev "$dev" protocol ip parent 1:0 prio 1 u32 match ip src "$private_ip" flowid 1:"$class_id"
      if [ $? -ne 0 ]; then
        echo "Failed to add tc filter for source IP $private_ip" >&2
        # Rollback class addition
        sudo tc class del dev "$dev" parent 1: classid 1:"$class_id"
        return 1
      fi
    }

    add_job() {
      local job_id="$1"
      local job_file="/var/run/oyster-jobs/$job_id"

      sudo mkdir -p "/var/run/oyster-jobs"
      sudo touch "$job_file"
      sudo chmod 644 "$job_file"
    }

    job_exists "$JOB_ID"
    if [ $? -eq 0 ]; then
      exit 0
    fi

    check_and_update_bandwidth "$BANDWIDTH" "$INSTANCE_BANDWIDTH"

    if [ $? -ne 0 ]; then
      exit 1
    fi

    add_tc_rules "$PRIVATE_IP" "$BANDWIDTH"
    if [ $? -ne 0 ]; then
      free_bandwidth_usage "$BANDWIDTH"
      exit 1
    fi

    add_job "$JOB_ID"

  '';

  remove_rl = pkgs.writeShellScriptBin "remove_rl" ''

     if [ $# -ne 3 ]; then
      echo "Usage: $0 <job_id> <private_ip> <bandwidth>"
      exit 1
    fi

    JOB_ID="$1"
    PRIVATE_IP="$2"
    BANDWIDTH="$3"

    source ${common_rl}

    job_exists "$JOB_ID"
    if [ $? -ne 0 ]; then
      exit 0
    fi
    remove_job "$JOB_ID"
    remove_tc_rules "$PRIVATE_IP"
    free_bandwidth_usage "$BANDWIDTH"

  '';
in

pkgs.symlinkJoin {
  name = "rl-scripts";
  paths = [ add_rl remove_rl ];
}
