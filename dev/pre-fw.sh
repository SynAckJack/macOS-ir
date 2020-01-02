#!/usr/bin/env bash
# - bash/IR-Scripts/pre-collect.sh

# This script is intended to be run before any collection is started. Some tasks must be executed before the firewall can be started and so this is where this script comes into play.
#These tasks include checking latest version of tools, e.g MRT, XProtect, etc. alongside latest versions of macOS and Security Updates.

set -euo pipefail

#THESE COMMENTS CAN PROBABLY ONLY BE INCLUDED IN THE ENTRYPOINT FILE
# -e force the script to exit immediately if any non-zero (!= 0) exit code is returned
# -u prevents the use of undefined variables (other than $*, $@)
# -o pipefail forces the script to return a non-zero exit code if any part of a pipe fails


#Set colours for easy spotting of errors

#THESE NEED CHANGED - MAYBE ICONS?!
ERROR=$(echo -en '\033[01;31m')
PASS=$(echo -en '\033[01;32m')
NC=$(echo -en '\033[0m')
#WARN=$(echo -en '\033[1;33m')
INFO=$(echo -en '\033[01;35m')

#Check if sudo 
function check_sudo_permission {
	echo "${INFO}Checking if sudo user...${NC}"

	if [ "$EUID" -ne 0 ]; then
		echo "${PASS}Congrats!${NC}"
		return 0
	else
		echo "${ERROR}Please run with sudo...${NC}"
		return 1
	fi 
}

#Check version of macOS
function check_macOS_version {

	local version

	version="$(sw_vers -productVersion)"

	echo "${INFO}Checking macOS version...${NC}"

	if [[ "${version}" ]]; then
		echo "Currently installed macOS version: $version"
	else
		return 1
	fi

}

#Check if there are any macOS software/security updates available (2.)
function check_macOS_update {

	echo "${INFO}Checking for software updates...${NC}"

	# shellcheck disable=SC2143
	if [ "$(softwareupdate -l | grep -c 'No new')" ]; then
		echo "No update available"
	fi

}

function main {

	check_sudo_permission
	check_macOS_version
	check_macOS_update
}

main "$@"


