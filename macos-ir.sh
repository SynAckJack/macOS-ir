#!/usr/bin/env bash
# macOS-ir/macos-ir.sh 

# Collect and analyse data of a macOS Catalina (10.15.x) device to be used to assist with Incident Response.

set -euo pipefail

# Colours for output
FAIL=$(echo -en '\033[01;31m[-]\033[0m')
INFO=$(echo -en '\033[01;35m[*]\033[0m')
WARN=$(echo -en '\033[1;33m[!]\033[0m')

# Internal Field Seperator
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
	echo -e "  Collect, skipping file hashes, and store on usb:"
	echo -e "	    ./macos-ir collect -s -u myUSB\\n"
    echo -e "  Receive data using nc:"
    echo -e "       ./macos-ir analysis -n 5555\\n"
    echo -e "  Analyse data from local disk image:"
    echo -e "       ./macos-ir analysis -d [path to directory]/output.dmg\\n"
	
}

function install_tools {

	# Check if the required tools are installed. If not, install them.
	# Installs Xcode Tools and Homebrew. Brewfile (macOS-ir/Brewfile) used by Homebrew.

	echo -e "\n${INFO} Installing XCode Tools"
	echo "-------------------------------------------------------------------------------"

	if xcode-select --install  2> /dev/null | grep -q 'install requested'; then
		echo "XCode Tools must be installed. Please follow the opened dialog and then re-run on completion."
		exit 1
	fi

	if ! [[ "$(command -v brew)" > /dev/null ]] ; then

		# Install Homebrew
		echo -e "\n${INFO} Installing Homebrew"
		echo "-------------------------------------------------------------------------------"
		if ! /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" ; then

			echo "${FAIL} Failed to install Homebrew..."
			exit 1
		fi
	fi

	echo -e "\n${INFO} Installing Tools Using Homebrew"
	echo "-------------------------------------------------------------------------------"

	brew update >> /dev/null

	brew upgrade >> /dev/null

	brew bundle --file Brewfile


}

function main {
	
	# Validate user input and begin either collection or analysis

	var=${1:-"usage"}
	SKIP=false

	case "${var}" in
		collect ) 
			shift


			if [[ "${2:-"false"}" == "-s" ]] ; then
				# User entered -s, skip var set to true
				SKIP="true"
			fi

			# User wishes to beginc collection. Validate input and execute collect.sh with specified flags
			while getopts ":hdnu" opt; do
				case ${opt} in
					h ) usage
						;;

					d ) echo "${WARN} Sudo permissions required..."
						sudo ./collect.sh -d "${SKIP}"
						;;

					n ) local ipPort=${2:-"none"}; 
						
						if ! [ "${ipPort}" == "none" ] ; then

							# Seperate IP address and port
							# Makes for easier parsing
							ip=$(echo "${ipPort}" | awk -F ":" ' { print $1 } ')
							port=$(echo "${ipPort}" | awk -F ":" ' { print $2 } ')

							# Set Internal Field Seperator
							IFS="."

							read -r -a ipArray <<< "$ip"

							#Verify data provided is a valid IP and port
							if [[ ${ipArray[0]} -le 255 ]] &&  [[ ${ipArray[1]} -le 255 ]] && [[ ${ipArray[2]} -le 255 ]] && [[ ${ipArray[3]} -le 255 ]] && [[ ${port} -le 65365 ]]; then

								echo "${WARN} Sudo permissions required..."
								sudo ./collect.sh -n "${ipPort}" "${SKIP}"
							else
								echo "${FAIL} Please provide a valid IP address and port. Exiting..."
								exit 1
							fi
						else 
							echo "${FAIL} Please provide a disk name. Exiting..."
							exit 1
						fi
						;;

					u ) local disk=${2:-"none"};

						if ! [ "${disk}" == "none" ] ; then

							# Verify that the provided disk name exists
							if [[ -e /Volumes/"${disk}" ]] ; then
								echo "${WARN} Sudo permissions required..."
								sudo ./collect.sh -u "${disk}" "${SKIP}"
							else
								echo "${FAIL} Provided disk does not exist. Exiting..."
								exit 1
							fi
						else 
							echo "${FAIL} Please provide a disk name. Exiting..."
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

			# User wishes to begin analysis.
			while getopts ":hdnui" opt; do
				case ${opt} in
					h ) usage
						;;
					d ) local diskImage=${2:-"none"};

						if ! [ "${diskImage}" == "none" ] ; then
							install_tools
							echo "${WARN} Sudo permissions required..."
							sudo ./analysis.sh -d "${diskImage}"
						else
							echo "${FAIL} Please provide a disk name. Exiting..."
						fi
						;;

					n ) local port=${2:-"none"};

						if ! [ "${port}" == "none" ] ; then
							install_tools
							echo "${WARN} Sudo permissions required..."
							sudo ./analysis.sh -n "${port}"
						else
							echo "${FAIL} Please provide a port. Exiting..."
						fi
						;;

					u ) local disk=${2:-"none"};

						if ! [ "${disk}" == "none" ] ; then

							if [[ -e /Volumes/"${disk}" ]] ; then
								install_tools
								echo "${WARN} Sudo permissions required..."
								sudo ./analysis.sh -u "${disk}"
							else
								echo "${FAIL} Provided disk does not exist. Exiting..."
								exit 1
							fi
						else 
							echo "${FAIL} Please provide a disk name. Exiting..."
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