#!/usr/bin/env bash

#The following script will erase a disk passed to allow for preperation to copy retrieved data. It will format the drive in HFS+ and also encrypt this with a random password.

set -euo pipefail
# -e exit if any command returns non-zero status code
# -u prevent using undefined variables
# -o pipefail force pipelines to fail on first non-zero status code

FAIL=$(echo -en '\033[01;31m')
PASS=$(echo -en '\033[01;32m')
NC=$(echo -en '\033[0m')
INFO=$(echo -en '\033[01;35m')

function main {

	local disk=${1:-"none"}

	if [ "${disk}" == "none" ] ; then
		local directory

		directory="$HOME/$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')"

		echo "${INFO}[*]${NC} No disk provided. Creating directory at ${directory}"

		if [[ ! -e "$directory" ]] ; then
			mkdir "$directory"
			# succseffuly created. Now copy data to this directory. Once all collected get total size of folder and then create an encrypted disk image with random password.
		else 
			echo "${FAIL}[-]${NC} $(directory) already exists. Exiting..."
			exit 1
		fi


	else
		true
	fi 

}

main "$@"