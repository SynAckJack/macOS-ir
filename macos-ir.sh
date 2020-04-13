#!/usr/bin/env bash

set -euo pipefail
# -e exit if any command returns non-zero status code
# -u prevent using undefined variables
# -o pipefail force pipelines to fail on first non-zero status code

FAIL=$(echo -en '\033[01;31m')
# PASS=$(echo -en '\033[01;32m')
NC=$(echo -en '\033[0m')
INFO=$(echo -en '\033[01;35m')
WARN=$(echo -en '\033[1;33m')

SKIP=false

IFS=$'\n'

function usage {
	
	echo -e "                           ____  _____       ________  "
	echo -e "     ____ ___  ____ ______/ __ \/ ___/      /  _/ __ \ "
	echo -e "    / __ \`__ \/ __ \`/ ___/ / / /\__ \______ / // /_/ / "
	echo -e "   / / / / / / /_/ / /__/ /_/ /___/ /_____// // _, _/ "
	echo -e "  /_/ /_/ /_/\__,_/\___/\____//____/     /___/_/ |_|  \\n"

	echo -e "  Collect or analyse data from a macOS system. For use during "
	echo -e "  Incident Respose. Generates PDF's after analysis to assist with "
	echo -e "  identifying a threat.\\n"

	echo -e "  usage: ./macos-ir.sh [-h | collect | analysis] [-options]\\n"

	echo -e "    -h    - Show this message\\n"

	echo -e "  collect:\\n"
	echo -e "    -s    - Skip reading permissions of files and generating hashes."
	echo -e "	    Reduces overall execution time.\\n"
	echo -e "    -u    - Copy extracted data to provided USB drive. "
	echo -e "	    Provided USB will be erased.\\n"
	echo -e "    -d    - Copy extracted data to a disk image. "
	echo -e "	    Disk image generated and encrypted using APFS\\n"
	echo -e "    -n    - Transfer collected data to another device using nc. "
	echo -e "	    Takes IP and port in format IP Address:Port\\n\\n"

	echo -e "  analysis:\\n"
	echo -e "    -u    - Analyse data stored on an external drive. "
	echo -e "	    Provide only USB name.\\n"
	echo -e "    -d    - Analyse data stored on a disk image."
	echo -e "	    Provide only disk image path.\\n"
	echo -e "    -n    - Receive collected data from nc. "
	echo -e "	    Takes only listening port.\\n"
	echo -e "    -i    - Install analysis tools. "
	echo -e "	    Installs XCode Tools and a range of other tools that are "
	echo -e "	    required for analysis (using Homebrew).\\n"

	echo -e "  Example: "
	echo -e "  Collect and transmit using nc to localhost port 5555:"
	echo -e "	    ./macos-ir collect -n 127.0.0.1:5555\\n"
	echo -e "  Receive data using nc:"
	echo -e "	    ./macos-ir analysis -n 5555\\n"
	echo -e "  Collect, skipping file hashes, and store on usb:"
	echo -e "	    ./macos-ir collect -s -u myUSB\\n"
	
}

function install_tools {

	echo -e "\n${INFO}[*]${NC} Installing XCode Tools"
	echo "-------------------------------------------------------------------------------"

	if xcode-select --install  2> /dev/null | grep -q 'install requested'; then
		echo "XCode Tools must be installed. Please follow the opened dialog and then re-run on completion."
		exit 1
	fi

	if ! [[ "$(command -v brew)" > /dev/null ]] ; then

		echo -e "\n${INFO}[*]${NC} Installing Homebrew"
		echo "-------------------------------------------------------------------------------"
		if ! /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" ; then

			echo "${FAIL}[-]${NC} Failed to install Homebrew..."
			exit 1
		fi
	fi

	echo -e "\n${INFO}[*]${NC} Installing Tools Using Homebrew"
	echo "-------------------------------------------------------------------------------"

	brew update >> /dev/null

	brew upgrade >> /dev/null

	brew bundle --file Brewfile


}

function main {
	
	var=${1:-"usage"}

	case "${var}" in
		collect ) 
			shift

			if [[ ${1} == "-s" ]] ; then
				SKIP="true"
				shift
			fi

			while getopts ":hdnu" opt; do
				case ${opt} in
					h ) usage
						;;

					d ) echo "collect disk" 
						echo "${WARN}[!]${NC} Sudo permissions required..."
						sudo ./collect.sh -d "${SKIP}"
						;;

					n ) local ipPort=${2:-"none"}; 
						
						if ! [ "${ipPort}" == "none" ] ; then

							ip=$(echo "${ipPort}" | awk -F ":" ' { print $1 } ')
							port=$(echo "${ipPort}" | awk -F ":" ' { print $2 } ')

							IFS="."

							read -r -a ipArray <<< "$ip"

							if [[ ${ipArray[0]} -le 255 ]] &&  [[ ${ipArray[1]} -le 255 ]] && [[ ${ipArray[2]} -le 255 ]] && [[ ${ipArray[3]} -le 255 ]] && [[ ${port} -le 65365 ]]; then

								echo "${WARN}[!]${NC} Sudo permissions required..."
								sudo ./collect.sh -n "${ipPort}" "${SKIP}"
							else
								echo "${FAIL}[-]${NC} Please provide a valid IP address and port. Exiting..."
								exit 1
							fi
						else 
							echo "${FAIL}[-]${NC} Please provide a disk name. Exiting..."
							exit 1
						fi
						;;

					u ) local disk=${2:-"none"};

						if ! [ "${disk}" == "none" ] ; then

							if [[ -e /Volumes/"${disk}" ]] ; then
								echo "${WARN}[!]${NC} Sudo permissions required..."
								sudo ./collect.sh -u "${disk}" "${SKIP}"
							else
								echo "${FAIL}[-]${NC} Provided disk does not exist. Exiting..."
								exit 1
							fi
						else 
							echo "${FAIL}[-]${NC} Please provide a disk name. Exiting..."
							exit 1
						fi
						;;

					\?) echo "Invalid option -- $OPTARG "
						usage
						;;

					* ) usage
						;;
				esac
			done
			;;

		analysis ) 
			shift 

			while getopts ":hdnui" opt; do
				case ${opt} in
					h ) usage
						;;
					d ) local diskImage=${2:-"none"};

						if ! [ "${diskImage}" == "none" ] ; then
							install_tools
							echo "${WARN}[!]${NC} Sudo permissions required..."
							sudo ./analysis.sh -d "${diskImage}"
						else
							echo "${FAIL}[-]${NC} Please provide a disk name. Exiting..."
						fi
						;;

					n ) local port=${2:-"none"};

						if ! [ "${port}" == "none" ] ; then
							install_tools
							echo "${WARN}[!]${NC} Sudo permissions required..."
							sudo ./analysis.sh -n "${port}"
						else
							echo "${FAIL}[-]${NC} Please provide a port. Exiting..."
						fi
						;;

					u ) local disk=${2:-"none"};

						if ! [ "${disk}" == "none" ] ; then

							if [[ -e /Volumes/"${disk}" ]] ; then
								install_tools
								echo "${WARN}[!]${NC} Sudo permissions required..."
								sudo ./analysis.sh -u "${disk}"
							else
								echo "${FAIL}[-]${NC} Provided disk does not exist. Exiting..."
								exit 1
							fi
						else 
							echo "${FAIL}[-]${NC} Please provide a disk name. Exiting..."
							exit 1
						fi
						;;

					i ) install_tools
						;;

					\?) echo "Invalid option -- $OPTARG "
						usage
						;;

					* ) usage
						;;
				esac
			done 
			;;

		tools ) install_tools
			;;

		* ) usage
			;;
	esac
}

main "$@"