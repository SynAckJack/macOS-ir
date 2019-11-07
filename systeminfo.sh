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
function output_to_file() {

	for i in "${output[@]}" ; do
		echo "${i}" >> output.txt
	done

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
		output+=("${PASS}[+]${NC} Currently installed macOS version: $version")
	else
		return 1
	fi

}

#Check if there are any macOS software/security updates available (2.)
function check_macOS_update {

	echo "${INFO}[*]${NC} Checking for software updates..."

	echo "${INFO}[*]${NC} Checking internet connection..."
	if ping -q -c 1 -W 1 8.8.8.8 >/dev/null ; then
		output+=("${FAIL}[-]${NC} No internet connection. Skipping...")
		return
	else
		output+=("${PASS}[+]${NC} Intenet connected. Continuing...")
	fi
	# shellcheck disable=SC2143
	if [ "$(softwareupdate -l | grep -c 'No new')" ]; then
		output+=("${PASS}[+]${NC} No updates available...")
	else
		output+=("${WARN}[!]${NC} Updates available...")
	fi

}

# https://eclecticlight.co/2018/06/02/how-high-sierra-checks-your-efi-firmware/
function check_efi {

	echo "${INFO}[*]${NC} Checking EFI Integrity..."
	#shellcheck disable=SC2143
	if [ "$(/usr/libexec/firmwarecheckers/eficheck/eficheck \
		--integrity-check | grep -c 'No changes')" ] ; then
	 	output+=("${PASS}[+]${NC} EFI integrity passed...")
	 else
	 	output+=("${FAIL}[-]${NC} EFI integrity failed!")
	fi
}

# http://osxdaily.com/2017/05/01/check-xprotect-version-mac/
function check_xprotect_last_updated {

	local date

	echo "${INFO}[*]${NC} Checking XProtect last updated..."

	#shellcheck disable=2012
	date="$(ls -l /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist | awk -F " " ' { print $6" "$7" "$8 } ')"

	output+=("${PASS}[+]${NC} XProtect last updated: ${date}")
}

function check_install_history {

	local history

	echo "${INFO}[*]${NC} Checking Application install history.."
	#https://news.ycombinator.com/item?id=20407233, 13/9/19
	history="$(system_profiler SPInstallHistoryDataType)"
	if [ -n "${history}" ] ; then
		output+=("${PASS}[+]${NC} ${history}")
	else
		output+=("${INFO}[*]${NC} No install history...")
	fi
}

function check_mrt_update {
	#(https://eclecticlight.co/2018/09/28/silent-mojave-night-security-settings-files-in-macos-mojave/)

	local mrt

	echo "${INFO}[*]${NC} Checking MRT last updated..."
	#https://news.ycombinator.com/item?id=20407233, 13/9/19 (up until 'grep'. Everything else was me)
	mrt="$(softwareupdate --history --all | grep MRT | awk -F "softwareupdated" 'NR > 1 { exit }; 1' | awk -F " " ' { print $2 } ')"

	if [ -n "${mrt}" ] ; then
		output+=("${PASS}[+]${NC} Current MRT version: ${mrt}")
	else
		output+=("${FAIL}[-]${NC} Couldn't detect MRT version...")
	fi
}

function check_sip {

	echo "${INFO}[*]${NC} Checking System Integrity Protection status..."

	if csrutil status | grep -q 'enabled' ; then
		output+=("${PASS}[+]${NC} System Integrity Protection enabled.")
	else
		output+=("${FAIL}[-]${NC} System Integrity Protection disabled.")
	fi
}

function check_firewall {

	local firewall
	local stealthFirewall

	echo "${INFO}[*]${NC} Checking firewall status..."

	firewall="$(defaults read /Library/Preferences/com.apple.alf globalstate)"

	if [[ "${firewall}" -ge 1 ]] ; then
		output+=("${PASS}[+]${NC} Firewall enabled.")
	else 
		output+=("${FAIL}[-]${NC} Firewall disabled.")
	fi

	stealthFirewall="$(defaults read /Library/Preferences/com.apple.alf stealthenabled)"

	if [[ "${stealthFirewall}" -eq 1 ]] ; then
		output+=("${PASS}[+]${NC} Stealth firewall enabled.")
	else 
		output+=("${FAIL}[-]${NC} Stealth firewall disabled.")
	fi
}

function main {

	local var=${1:-"usage"}

	declare -a output

	check_sudo_permission

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

	elif [[ "${var}" = "all" ]] ; then
		check_macOS_version
		check_macOS_update
		check_efi
		check_xprotect_last_updated
		check_install_history
		check_mrt_update
		check_sip
		check_firewall
		output_to_file output[@]
	else
		usage
	fi
	
}

main "$@"