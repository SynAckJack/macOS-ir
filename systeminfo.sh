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

# http://osxdaily.com/2017/05/01/check-xprotect-version-mac/
function check_xprotect_last_updated {

	local date

	echo "${INFO}[*]${NC} Checking XProtect last updated..."

	#shellcheck disable=2012
	date="$(ls -l /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist | awk -F " " ' { print $6" "$7" "$8 } ')"

	echo "${PASS}[+]${NC} XProtect last updated: ${date}"
}

function check_install_history {

	local history

	#https://news.ycombinator.com/item?id=20407233, 13/9/19
	history="$(system_profiler SPInstallHistoryDataType)"
	if [ -n "${history}" ] ; then
		echo "${INFO}[*]${NC} ${history}"
	else
		echo "${INFO}[*]${NC} No install history..."
	fi
}

function check_mrt_update {
	#(https://eclecticlight.co/2018/09/28/silent-mojave-night-security-settings-files-in-macos-mojave/)

	local mrt

	#https://news.ycombinator.com/item?id=20407233, 13/9/19 (up until 'grep'. Everything else was me)
	mrt="$(softwareupdate --history --all | grep MRT | awk -F "softwareupdated" 'NR > 1 { exit }; 1' | awk -F " " ' { print $2 } ')"

	if [ -n "${mrt}" ] ; then
		echo "${PASS}[+]${NC} Current MRT version: ${mrt}"
	else
		echo "${FAIL}[-]${NC} Couldn't detect MRT version..."
	fi
}

function check_sip {

	if csrutil status | grep -q 'enabled' ; then
		echo "${PASS}[+]${NC} System Integrity Protection enabled..."
	else
		echo "${FAIL}[-]${NC} System Integrity Protection disabled..."
	fi
}
function main {

	local var=${1:-"usage"}

	if [[ "${var}" = "version" ]] ; then
		check_macOS_version

	elif [[ "${var}" = "update" ]] ; then
		check_macOS_update

	elif [[ "${var}" = "efi" ]] ; then
		check_efi

	elif [[ "${var}" = "xprotect" ]] ; then
		check_xprotect_last_updated

	elif [[ "${var}" = "install" ]] ; then
		check_install_history

	elif [[ "${var}" = "mrt" ]] ; then
		check_mrt_update

	elif [[ "${var}" = "sip" ]] ; then
		check_sip

	else
		usage
	fi
	
}

main "$@"