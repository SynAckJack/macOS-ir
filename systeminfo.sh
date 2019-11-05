#!/usr/bin/env bash

set -euo pipefail

FAIL=$(echo -en '\033[01;31m')
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
	echo "${INFO}[*]${NC} Checking if sudo user..."

	if [ "$EUID" -ne 0 ]; then
		echo "${FAIL}[-]${NC} Sudo perimissions are required. Please run again with sudo..."
		return 1
	else
		
		echo "${PASS}[+]${NC} Running as sudo..."
		return 0
	fi 
}

#Check version of macOS
function check_macOS_version {

	local version

	version="$(sw_vers -productVersion)"

	echo "${INFO}[*]${NC} Checking macOS version..."

	if [[ "${version}" ]]; then
		echo "${PASS}[+]${NC} Currently installed macOS version: $version"
	else
		return 1
	fi

}

#Check if there are any macOS software/security updates available (2.)
function check_macOS_update {

	echo "${INFO}[*]${NC} Checking for software updates..."

	# shellcheck disable=SC2143
	if [ "$(softwareupdate -l | grep -c 'No new')" ]; then
		echo "${PASS}[+]${NC} No updates available..."
	else
		echo "${WARN}[!]${NC} Updates available..."
	fi

}

# https://eclecticlight.co/2018/06/02/how-high-sierra-checks-your-efi-firmware/
function check_efi {

	echo "${INFO}[*]${NC} Checking EFI Integrity..."
	#shellcheck disable=SC2143
	if [ "$(/usr/libexec/firmwarecheckers/eficheck/eficheck \
		--integrity-check | grep -c 'No changes')" ] ; then
	 	echo "${PASS}[+]${NC} EFI integrity passed..."
	 else
	 	echo "${FAIL}[-]${NC} EFI integrity failed!"
	fi
}

function main {

	check_sudo_permission
	check_macOS_version
	check_macOS_update
	check_efi
}

main "$@"