#!/usr/bin/env bash

set -euo pipefail

ERROR=$(echo -en '\033[01;31m')
PASS=$(echo -en '\033[01;32m')
NC=$(echo -en '\033[0m')
#WARN=$(echo -en '\033[1;33m')
INFO=$(echo -en '\033[01;35m')

function usage {
	cat << EOF
Usage:
	mrt			-Check MRT Version
	install			-Check Install History
	xprotect		-Check Xprotect Version
	efi			-Check EFI Integrity
EOF
		exit 0
}

#Check if sudo 
function check_sudo_permission {
	echo "${INFO}[*]${NC} Checking if sudo user...${NC}"

	if [ "$EUID" -ne 0 ]; then
		echo "${ERROR}[-]${NC} Sudo perimissions are required. Please run again with sudo..."
		return 1
	else
		
		echo "${PASS}[+]${NC} Running as sudo...${NC}"
		return 0
	fi 
}

#Check version of macOS
function check_macOS_version {

	local version

	version="$(sw_vers -productVersion)"

	echo "${INFO}[*]${NC} Checking macOS version...${NC}"

	if [[ "${version}" ]]; then
		echo "${PASS}[+]${NC} Currently installed macOS version: $version"
	else
		return 1
	fi

}

function main {

	check_sudo_permission
	check_macOS_version
	
}

main "$@"