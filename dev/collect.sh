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
declare -a LOGS


function usage {
	cat << EOF
./collect.sh [-u | -n | -d | -h] [USB Name | IP Address:Port]
Usage:
	-h		- Show this message
	-u		- Copy extracted data to provided USB drive. ** NOTE: DRIVE WILL BE ERASED **
	-d		- Copy extracted data to a disk image. ** NOTE: This disk image will be created using APFS and encrypted **
	-n		- Transfer collected data to another device using nc. Takes IP and Port in format <IP ADDRESS>:<PORT>

** NOTE: For collection to access all files, 'Full Disk Access' needs to be given to Terminal.app. If not, some data will be missing **
	
EOF
		exit 0
}
function log {
	
	local type
	local message

	type=$1
	message=$2
	if [[ ! ${type} == "FINISHED" ]] ; then
		LOGS+=("$(date +%H:%M:%S), ${type}, ${message}")
	else
		LOGS+=("$(date +%H:%M:%S), ${type}, ${message}")
		lHostName="$(scutil --get LocalHostName)"

		for i in "${LOGS[@]}" ; do
			echo "	${i}"  >> "${lHostName}-$(date +%H:%M:%S)-LOG.csv"
		done
	fi
}

function collect {
	
	echo "${INFO}[*]${NC} Started collection...Writing to collect.log"
	log "INFO" "Started Collection"
}

function disk {
	
	local directory
	local passphrase
	local dirSize

		directory="$HOME/$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')"

		echo "${INFO}[*]${NC} Creating directory at ${directory}"
		log "INFO" "Started 'disk'"

		if [[ ! -e "$directory" ]] ; then
			mkdir "$directory" && cd "$directory"

			# COLLECT

			echo "${INFO}[*]${NC} Collected data. Creating disk image..."
			log "INFO" "Creating disk image"

			dirSize=$(du -sk . | tr -cd '[:digit:]')
			echo "$PWD"
			dirSize=$((dirSize + 102400))

			passphrase=$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')
			# PERFORM MD5 HASH

			if echo -n "${passphrase}" | hdiutil create -fs apfs -size "${dirSize}"kb -stdinpass -encryption AES-128 -srcfolder "${directory}" "${directory}/output".dmg  ; then
				echo "${PASS}[+]${NC} Succesfully created disk image with data at ${directory}/output.dmg."
				log "PASS" "Disk image created. Directory: ${directory}, Passphrase: ${passphrase}"

				echo "${INFO}[*]${NC} Passphrase for image: ${passphrase}"
			else
				echo "${FAIL}[-]${NC} Failed to create disk image. Exiting..."
				log "ERROR" "Disk image creation failed"
				exit 1
			fi
			
		else 
			echo "${FAIL}[-]${NC} $(directory) already exists. Exiting..."
			log "ERROR" "${directory} exists"
			exit 1
		fi
}

function usb {

	local disk=${1}	

	log "INFO" "Started 'usb'"
	if [ ! "${disk}" == "none" ] ; then

		echo "${INFO}[*]${NC} Checking disk ${disk}..."
		log "INFO" "Validating USB"

		if [[ -e /Volumes/"${disk}" ]] ; then
			echo "${WARN}[!]${NC} Continuing will erase this disk, proceeding in 5 seconds..."
			sleep 5
			echo "${PASS}[+]${NC} Continuing..."

			passphrase="$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')"

			if diskutil apfs eraseVolume "${disk}" -name "${disk}" -passphrase "${passphrase}" >>/dev/null  ; then
				lHostName="$(scutil --get LocalHostName)"

				echo "${INFO}[*]${NC} Disk erased. Passphrase: ${passphrase}"
				log "INFO" "USB prepared. Passphrase: ${passphrase}"
				#COLLECT

				echo "${INFO}[*]${NC} Performing md5 hash of files..."
				log "INFO" "MD5 started"

				if find . -type f -exec md5sum '{}' \; >> "${lHostName}"-md5sum.txt ; then
					echo "${PASS}[+]${NC} MD5 hash complete. Stored in: ${lHostName}-md5.txt"
					log "PASS" "MD5 completed"
				else
					echo "${WARN}[!]${NC} MD5 hash failed. Continuing..."
					log "WARNING" "MD5 failed"
				fi

				if tar cvf /Volumes/"${disk}"/output.tar ./* > /dev/null 2>&1 ; then
					echo "${PASS}[+]${NC} Data successfully copied..."
					log "PASS" "Data copied to USB successfully"
				else
					echo "${FAIL}[-]${NC} Failed to copy data. Exiting..."
					log "ERROR" "Failed to copy data to USB"
					exit 1
				fi
					
			fi 
		else
			echo "${FAIL}[-]${NC} Provided disk does not exist. Exiting..."
			log "ERROR" "USB does not exist"
			exit 1
		fi
	else
		echo "${FAIL}[-]${NC} Please provide a disk name. Exiting..."
		log "ERROR" "USB name not provided"
		exit 1
	fi
}

function network {
	
	local ipPort=${1}
	local port
	local passphrase
	local lHostName
	local directory

	log "INFO" "Started 'network'"

	echo "${INFO}[*]${NC} Checking IP Address..."

	if [ ! "${ip}" == "none" ] && [[ "${ip}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\:[0-9]{1,5}$ ]] ; then

		ip=$(echo "${ipPort}" | awk -F ":" ' { print $1 } ')
		port=$(echo "${ipPort}" | awk -F ":" ' { print $2 } ')

		IFS="."

		read -r -a ipArray <<< "$ip"

		if [[ ${ipArray[0]} -le 255 ]] &&  [[ ${ipArray[1]} -le 255 ]] && [[ ${ipArray[2]} -le 255 ]] && [[ ${ipArray[3]} -le 255 ]]; then
			echo "YAY2"
			log "INFO" "IP Address valid"
		else
			echo "${FAIL}[-]${NC} Please provide a valid IP address and port. Exiting..."

			log "ERROR" "IP Address not valid"
			exit 1
		fi

		IFS=$'\n'

		directory="$HOME/$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')"

		echo "${INFO}[*]${NC} Creating temporary directory at ${directory}"
		log "INFO" "Temporary directory created at ${directory}"
	
		if [[ ! -e "$directory" ]] ; then
			mkdir "$directory" && cd "$directory"
		else
			echo "${FAIL}[-]${NC} Failed to create directory. Exiting..."
			log "ERROR" "Couldn't create directory ${directory}"
			exit 1
		fi

		# COLLECTION

		collect

		# Compress files
		if tar cvf output.tar ./* > /dev/null 2>&1 ; then
			lHostName="$(scutil --get LocalHostName)"
			passphrase=$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')
			if openssl enc -e -aes256 -in output.tar -out "${lHostName}".tar -pass pass:"${passphrase}"; then
				echo "${PASS}[+]${NC} Successfully compressed and encrypted data. Passphrase: ${passphrase}"
				log "INFO" "Data compressed and encrypted. Passphrase: ${passphrase}"
				rm output.tar
			else
				echo "${FAIL}[-]${NC} Failed to encrypt data. Exitting..."
				log "ERROR" "Couldn't encrypt data"
				exit 1
			fi
		else
			echo "${FAIL}[-]${NC} Failed to compress data. Exitting..."
			log "ERROR" "Couldn't compress data"
			exit 1
		fi
		
		echo "${INFO}[*]${NC} Performing md5 hash of files..."
		log "INFO" "MD5 started"

		if find . -type f -exec md5sum '{}' \; >> "${lHostName}"-md5sum.txt ; then
			echo "${PASS}[+]${NC} MD5 hash complete. Stored in: ${lHostName}-md5.txt"
			log "INFO" "MD5 completed"
		else
			echo "${WARN}[!]${NC} MD5 hash failed. Continuing..."
			log "WARN" "MD5 failed"
		fi

		echo "${INFO}[*]${NC} Starting nc transfer to ${ipPort}..."
		log "INFO" "netcat started"

		echo "${INFO}[*]${NC} Waiting on connection..."

		if tar -zcf - . | pv -f | nc -n "${ip}" "${port}" ; then
			echo "${PASS}[+]${NC} Successfully transferred data. Remember passphrase: ${passphrase}"
			log "INFO" "Data transferred successfully"
		fi
	else
		echo "${FAIL}[-]${NC} Please provide an IP address. Exiting..."
		log "ERROR" "No IP address provided"
		exit 1
	fi
}
function main {

	while getopts ":hdnu" opt; do
		case ${opt} in
			h ) usage
				;;
			d ) collect 
				;;
			n ) local ip=${2:-"none"}; network "${ip}"
				;;
			u ) local disk=${2:-"none"}; usb "${disk}"
				;;
			* ) usage
				;;
		esac
	done

	log "FINISHED" "Successfully completed ✅"

	# Add statement to check the number of arguments and if equal to 1 then call usage.
}

main "$@"