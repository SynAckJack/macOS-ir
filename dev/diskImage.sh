#!/usr/bin/env bash

#The following script will erase a disk passed to allow for preperation to copy retrieved data. It will format the drive in HFS+ and also encrypt this with a random password.

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
	./diskImage [-u | -n | -d | -h] [USB Name | IP Address:Port]
	Usage:
		-h		- Show this message
		-u		- Copy extracted data to provided USB drive. ** NOTE: DRIVE WILL BE ERASED **
		-d		- Copy extracted data to a disk image. ** NOTE: This disk image will be created using APFS and encrypted **
		-n		- Transfer collected data to another device using nc. Takes IP and Port in format <IP ADDRESS>:<PORT>
		
EOF
		exit 0
}

function disk {
	
	local directory
	local passphrase

		directory="$HOME/$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')"

		echo "${INFO}[*]${NC} No disk provided. Creating directory at ${directory}"

		if [[ ! -e "$directory" ]] ; then
			mkdir "$directory"
			# succseffuly created. Now copy data to this directory. Once all collected get total size of folder and then create an encrypted disk image with random password.
		else 
			echo "${FAIL}[-]${NC} $(directory) already exists. Exiting..."
			exit 1
		fi
}

function usb {

	local disk=${1}
	
	echo "${INFO}[*]${NC} Checking disk... ${disk}"

	if [ ! "${disk}" == "none" ] ; then

		if [[ -e /Volumes/"${disk}" ]] ; then
			echo "${WARN}[!]${NC} Continuing will erase this disk, proceeding in 5 seconds..."
			sleep 5
			echo "${PASS}[+]${NC} Continuing..."

			passphrase="$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')"

			if diskutil apfs eraseVolume "${disk}" -name Untitled -passphrase "${passphrase}" >>/dev/null  ; then
				echo "${INFO}[*]${NC} Disk erased. Passphrase: ${passphrase}"
			fi 
		else
			echo "${FAIL}[-]${NC} Provided disk does not exist. Exiting..."
		fi
	else
		echo "${FAIL}[-]${NC} Please prove a disk name. Exiting..."
	fi
}

function network {
	
	local ipPort=${1}
	local port
	local passphrase
	local lHostName

	echo "${INFO}[*]${NC} Checking IP Address..."

	ip=$(echo "${ipPort}" | awk -F ":" ' { print $1 } ')
	port=$(echo "${ipPort}" | awk -F ":" ' { print $2 } ')

	if [ ! "${ip}" == "none" ] && [[ "${ip}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] ; then

		IFS="."

		read -r -a ipArray <<< "$ip"

		if [[ ${ipArray[0]} -le 255 ]] &&  [[ ${ipArray[1]} -le 255 ]] && [[ ${ipArray[2]} -le 255 ]] && [[ ${ipArray[3]} -le 255 ]]; then
			echo "YAY2"
		else
			echo echo "${FAIL}[-]${NC} Please provide an IP address. Exiting..."
			exit 1
		fi

		IFS=$'\n'

		# COLLECTION

		# Compress files
		if tar cvf output.tar ./* > /dev/null 2>&1 ; then
			lHostName="$(scutil --get LocalHostName)"
			passphrase=$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')
			if openssl enc -e -aes256 -in output.tar -out "${lHostName}".tar.gz -pass pass:"${passphrase}"; then
				echo "${PASS}[+]${NC} Successfully compressed and encrypted data. Passphrase: ${passphrase}"
				rm output.tar
			else
				echo "${FAIL}[-]${NC} Failed to encrypt data. Exitting..."
				exit 1
			fi
		else
			echo "${FAIL}[-]${NC} Failed to compress data. Exitting..."
			exit 1
		fi
		
		echo "${INFO}[*]${NC} Performing md5 hash of files..."

		if find . -type f -exec md5sum '{}' \; >> "${lHostName}"-md5sum.txt ; then
			echo "${PASS}[+]${NC} MD5 hash complete. Stored in: ${lHostName}-md5.txt"
		else
			echo "${WARN}[!]${NC} MD5 hash failed. Continuing..."
		fi

		echo "${INFO}[*]${NC} Starting nc transfer to ${ipPort}..."

		echo "${INFO}[*]${NC} Waiting on connection..."

		if tar -zcf - . | pv -f | nc -n -w5 "${ip}" "${port}" ; then
			echo "${PASS}[+]${NC} Successfully transferred data. Remember passphrase: ${passphrase}"
		fi

	else
		echo "${FAIL}[-]${NC} Please provide an IP address. Exiting..."
		exit 1
	fi
}
function main {

	
	local passphrase

	
	while getopts ":hdnu" opt; do
		case ${opt} in
			h ) usage
				;;
			d ) disk 
				;;
			n ) local ip=${2:-"none"}; network "${ip}"
			;;
			u ) local disk=${2:-"none"}; usb "${disk}"
				;;
			\? ) usage
				;;
		esac
	done
}

main "$@"