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

function install_tools {

	echo -e "\n${INFO}[*]${NC} Installing XCode Tools"
	echo "-------------------------------------------------------------------------------"

	if xcode-select --install  2> /dev/null | grep -q 'install requested'; then
		echo "XCode Tools must be installed. Please follow the opened dialog and then re-run on completion."
		exit 1
	else
		echo "XCode Tools already installed."
	fi

	echo -e "\n${INFO}[*]${NC} Installing brew"
	echo "-------------------------------------------------------------------------------"
	#Install requirements for analysis. This will install XCode Tools alongside others.

	if ! [[ "$(command -v brew)" > /dev/null ]] ; then

		if /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" ; then
			echo "Homebrew installed!"
		else
			echo "Failed to install Homebrew..."
			exit 1
		fi
	fi
	echo "Homebrew installed!"
	brew update
	brew upgrade
	brew bundle
}

function check_hash {

	echo -e "\n${INFO}[*]${NC} Checking shasum of files"
	echo "-------------------------------------------------------------------------------"

	local shafile

	declare -a FAILEDHASHES

	shafile=$(find . -name "*-shasum.txt")

	while IFS=$'\n' read -r hash ; do 

		if echo "${hash}" | grep "FAILED" >> /dev/null; then
			FAILEDHASHES+=("${hash}")
		fi

	done < <(shasum -c "${shafile}")

	if [ "${#FAILEDHASHES[@]}" -gt 0 ] ; then
		echo "The following files failed checksum: "

		for i in "${FAILEDHASHES[@]}" ; do
			if echo "${i}" | grep -v -E "shasum.txt" ; then
				echo "${i}"
			else
				echo "Checksum file failed. This is due to the checksum file not containing a hash for itself. Don't worry about it..."	
			fi
		done
	else
		echo "All files passed checksum."
	fi

	
}

function read_file {

	filename="$1"

	if [ -e "${filename}" ] ; then

		while IFS=$'\n' read -r line; do

		if ! [ "${line}" == '' ] ; then
			LINES+=("$(echo "${line}" | cut -d':' -f 2-)")
		fi
		

		done < <(cat "${filename}")
	
	fi

}

function create_main_html {

	hostname=$(find . -name "*-shasum.txt" -print | cut -d '-' -f 1 | tr -d './')

		cat << EOF > "${reportDirectory}"/test.html
<!DOCTYPE html>

<html>

	<head>
	    <title>Analysis</title>
	</head>

	<style>
		html *
			{
			font-size: 1em !important;
			color: #000 !important;
			font-family: Arial;
		}

		h1 { 
			font-size: 2em !important;
			font-weight: bold !important;
		}

		@media print {
    		.pagebreak { 
    			page-break-before: always; 
    		} /* page-break-after works, as well */
		}

		pre {
		   font-family:monaco!important;
		   font-size: 9px;
		   line-height: 0.9;
		}

		toc {
			font-size: 14px;
		}

		pagetitle {
			font-size: 36px;
			align: left;
		}

	</style>

	<body>

	<h1 class="pagetitle" style="padding-top: 100px">${hostname} - Analysis Report</h1>
	<h2>$(date)</h2>

	<div class="pagebreak"></div>

	<div class="toc">
		<p align=centre><h1><b>Contents</b></h1></p>
			<ul class="toc_list">
				<li><a href="#systeminformation">System Information</a>
				<li><a href="#securityinformation">Security Information</a></li>
				<li><a href="#applicationinformation">Application Information</a></li>
				<li><a href="#installhistory">Install History</a></li>
				<li><a href="#hashes">Hashes of Executables</a></li>
				<li><a href="#browsers">Browsers</a></li>
				<ul>
					<li><a href="#browsers/safari">Safari</a></li>
					<li><a href="#browsers/chrome">Chrome</a></li>
					<li><a href="#browsers/firefox">Firefox</a></li>
				</ul>
				<li><a href="#disk">Disk Information</a></li>
				<li><a href="#cron">Cron Jobs</a></li>
				<li><a href="#launchagents">Launch Agents</a></li>
				<li><a href="#network">Network Information</a></li>
				<ul>
					<li><a href="#network/arp">ARP Table</a></li>
					<li><a href="#network/ifconfig">ifconfig</a></li>
					<li><a href="#network/connections">Network Connections</a></li>
				</ul>
				<li><a href="#user">User Information</a></li>
				<ul>
					<li><a href="#user/users">List of Users</a></li>
					<li><a href="#user/sudoers">Sudoers File</a></li>
					<li><a href="#user/last">Last Output</a></li>
				</ul>
			</ul>
	</div>

	<div class="pagebreak"></div>
EOF
}

function create_secondary_html {

	local title="$1"

	cat << EOF > "${reportDirectory}/${title}.html"

	<!DOCTYPE html>

<html>

	<head>
	    <title>${title}</title>
	</head>

	<style>
		html *
			{
			font-size: 1em !important;
			color: #000 !important;
			font-family: Arial;
		}

		h1 { 
			font-size: 2em !important;
			font-weight: bold !important;
		}

		@media print {
    		.pagebreak { 
    			page-break-before: always; 
    		} /* page-break-after works, as well */
		}

		pagetitle {
			font-size: 36px;
			align: left;
		}

	</style>

	<body>

	<h1 class="pagetitle" style="padding-top: 100px">${hostname} - ${title} Analysis Report</h1>
	<h2>$(date)</h2>

	<div class="pagebreak"></div>
EOF

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

function decrypt {
	
	local passphrase
	local tarFile

	tarFile=$(find . -name '*.tar' )	
	mkdir output

	echo "${INFO}[*]${NC} Decrypting .tar file. Please enter passphrase: "
	read -rp 'Passphrase: ' passphrase
 	
 	while [ "${passphrase}" != "q" ] ; do
 		echo "Attempting to decrypt with: ${passphrase}..."

 		if openssl enc -d -aes256 -in "${tarFile}" -pass pass:"${passphrase}" | tar xz -C output ; then
 			echo "${PASS}[+]${NC} Successfully decrypted .tar to directory: output."
 			break
 		else
 			echo "${WARN}[!]${NC} Failed to decrypt .tar. Please enter new passphrase or 'q' to exit..."
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
	
	local diskName
	local tarFile
	local passphrase

	diskName="$1"

	echo "${INFO}[*]${NC} Checking disk. Please enter the passphrase..."
	read -rp 'Passphrase: ' passphrase

	if echo -n "${passphrase}" | hdiutil attach "${diskName}" -stdinpass  ; then
		echo "${PASS}[+]${NC} Succesfully attached disk."
		log "PASS" "Disk mounted"
	else
		echo "${FAIL}[-]${NC} Incorrect passphrase. Exiting..."
		log "ERROR" "Disk mount failed"
		exit 1
	fi
}

function usb {
	
	local usbName
	local tarFile
	local passphrase

	usbName="$1"

	echo "${INFO}[*]${NC} Checking USB. Please enter the passphrase..."
	read -rp 'Passphrase: ' passphrase
 
	if diskutil apfs unlockVolume "${usbName}" -passphrase "${passphrase}"; then

		if cd /Volumes/"${usbName}" ; then
			echo "${PASS}[+]${NC} USB exists and is available. Locating .tar..."
			mkdir output
			if tar -xvf output.tar -C output ; then
				echo "${PASS}[+]${NC} .tar extracted to 'output' successfully..."
			else
				echo "${WARN}[!]${NC} Failed to extract .tar. Exiting..."
				exit 1
			fi	
		else
			echo "${FAIL}[-]${NC} Unable to access USB. Exiting..."
			exit 1
		fi
	else
		echo "${FAIL}[-]${NC} Incorrect passphrase. Exiting..."
		exit 1
	fi
}

function checkSudo {
	log "INFO" "Checking sudo permissions"

	echo "${INFO}[*]${NC} Checking sudo permissions..."

	if [ "$EUID" -ne 0 ] ; then
		echo "${FAIL}[-]${NC} Please run with sudo..."
 	 	exit 1
	fi

}

function main {

	checkSudo
	install_tools

	while getopts ":hdnu" opt; do
		case ${opt} in
			h ) usage
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