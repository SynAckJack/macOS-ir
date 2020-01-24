#!/usr/bin/env bash

set -euo pipefail
# -e exit if any command returns non-zero status code
# -u prevent using undefined variables
# -o pipefail force pipelines to fail on first non-zero status code

IFS=$'\n'

FAIL=$(echo -en '\033[01;31m')
PASS=$(echo -en '\033[01;32m')
NC=$(echo -en '\033[0m')
INFO=$(echo -en '\033[01;35m')
WARN=$(echo -en '\033[1;33m')

function usage {
	cat << EOF
./diskImage [-u | -n | -d | -h] [USB Name | Port | Disk Image Name]
Usage:
	-h		- Show this message
	-u		- Analyse data stored on an external drive.
	-d		- Analyse data stored on a disk image.
	-n		- Receive collected data from nc.
		
EOF
		exit 0
}

function decrypt {
	
	local passphrase
	local tarFile

	tarFile=$(find . -name '*.tar' )
	echo "${tarFile}"
	
	mkdir output

	echo "${INFO}[*]${NC} Decrypting .tar file. Please enter passphrase: "
	read -rp 'Passphrase: ' passphrase
 	
 	while [ "${passphrase}" != "q" ] ; do
 		echo "Attempting to decrypt with: ${passphrase}..."

 		if openssl enc -d -aes256 -in "${tarFile}" -pass pass:"${passphrase}" | tar xz -C output ; then
 			echo "${PASS}[+]${NC} Successfully decrypted .tar to directory: output."
 			break
 		else
 			echo "${FAIL}[-]${NC} Failed to decrypt .tar. Please enter new passphrase or 'q' to exit..."
 			read -rp 'Passphrase: ' passphrase
 		fi
  	done


}

function network {
	local port
	local passphrase

	echo "${INFO}[*]${NC} Checking valid port..."

	port=${1}

	if [[ "${port}" =~ ^[0-9]{1,5} ]] && [[ "${port}" -le 65535 ]] ; then
		
		echo "${INFO}[*]${NC} Connecting to nc on port ${port}..."

		if nc -l "${port}" | pv -f | tar -zxf - ; then
			echo "${PASS}[+]${NC} Successfully received data."

			decrypt
		else
			echo "${FAIL}[-]${NC} Failed to receive data. Exiting..."
			exit 1
		fi

	else
		echo "${FAIL}[-]${NC} Please enter a valid port. Exiting..."
		exit 1
	fi 
}

function disk {
	true
}

function usb {
	true
}

function requirements {
	#Install requirements for analysis. This will install XCode Tools alongside others.

	true
}

function main {

	while getopts ":hdnu" opt; do
		case ${opt} in
			h ) decrypt
				;;
			d ) local diskImage=${2:-"none"}; disk "${diskImage}"
				;;
			n ) local port=${2:-"none"}; network "${port}"
				 ;;
			u ) local disk=${2:-"none"}; usb "${disk}"
				;;
			\?) echo "Invalid option -- $OPTARG "
				usage
				;;
		esac
	done
}

main "$@"