#!/usr/bin/env bash
#~/scripts/dump.sh
#Created for testing small functions to be implemented in main scripts

ERROR=$(echo -en '\033[01;31m')
PASS=$(echo -en '\033[01;32m')
NC=$(echo -en '\033[0m')
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

# https://eclecticlight.co/2018/06/02/how-high-sierra-checks-your-efi-firmware/
function check_efi {

	echo "${INFO}Checking EFI Integrity...${NC}"
	#shellcheck disable=SC2143
	if [ "$(/usr/libexec/firmwarecheckers/eficheck/eficheck \
		--integrity-check | grep -c 'No changes')" ] ; then
	 	echo "${PASS}EFI integrity passed!${NC}"
	 else
	 	echo "${ERROR}EFI integrity failed!${NC}";
	fi
}

#CAN BE DONE OFFLINE
# http://osxdaily.com/2017/05/01/check-xprotect-version-mac/
function check_xprotect_last_updated {

	local date

	#shellcheck disable=2012
	date="$(ls -l /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist | awk -F " " ' { print $6" "$7" "$8 } ')"

	echo "XProtect last updated: ${date}"
}

function check_install_history {

	local history

	#https://news.ycombinator.com/item?id=20407233, 13/9/19
	history="$(system_profiler SPInstallHistoryDataType)"
	if [ -n "${history}" ] ; then
		echo "${history}"
	else
		echo "No History"
	fi
}


function check_mrt_update {
	#Could compare returned value with that from eclecticlight.co, although this may not be updated straight away and would it require permission?
	#(https://eclecticlight.co/2018/09/28/silent-mojave-night-security-settings-files-in-macos-mojave/)

	local mrt

	#https://news.ycombinator.com/item?id=20407233, 13/9/19 (up until 'grep'. Everything else was me)
	mrt="$(softwareupdate --history --all | grep MRT | awk -F "softwareupdated" 'NR > 1 { exit }; 1' | awk -F " " ' { print $2 } ')"

	if [ -n "${mrt}" ] ; then
		echo "Current MRT version: ${mrt}"
	else
		echo "${ERROR}Couldn't detect MRT version...${NC}"
	fi
}

function check_sip {

	if csrutil status | grep -q 'enabled' ; then
		echo "SIP Enabled"
	else
		echo "SIP Disabled"
	fi
}

function main {

	local var=${1:-"usage"}


	if [[ "${var}" = "mrt" ]] ; then
		check_mrt_update

	elif [[ "${var}" = "install" ]] ; then
		check_install_history

	elif [[ "${var}" = "xprotect" ]] ; then
		check_xprotect_last_updated

	elif [[ "${var}" = "efi" ]] ; then
		check_efi

	elif [[ "${var}" = "sip" ]] ; then
		check_sip

	else
		usage
	fi

	
}

main "$@"
