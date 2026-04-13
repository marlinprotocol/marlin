#!/bin/bash

set -euo pipefail

# Usage: ./update-vm.sh <ssh args> <user@ip>

echo "Updating $2"

ssh $1 $2 "DEBIAN_FRONTEND=noninteractive sudo apt update -y && sudo apt upgrade -y && sudo apt autoremove -y && sudo reboot && exit"
