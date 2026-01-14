#!/run/current-system/sw/bin/bash

if [ $# -ne 3 ]; then
    echo "Usage: $0 <job_id> <private_ip> <bandwidth>"
    exit 1
fi


JOB_ID="$1"
PRIVATE_IP="$2"
BANDWIDTH="$3"

source "$(dirname "$0")/common_rl.sh"

job_exists "$JOB_ID"
if [ $? -ne 0 ]; then
    exit 0
fi
remove_job "$JOB_ID"
remove_tc_rules "$PRIVATE_IP"
free_bandwidth_usage "$BANDWIDTH"