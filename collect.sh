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

declare -a LOGS
declare -a USERS

function log {
	
	local type
	local message

	type=$1
	message=$2
	if [[ ! ${type} == "FINISHED" ]] ; then
		LOGS+=("$(date +"%Y-%m-%dT%H:%M:%SZ"), ${type}, ${message}")
	else
		LOGS+=("$(date +"%Y-%m-%dT%H:%M:%SZ"), ${type}, ${message}")
		lHostName="$(scutil --get LocalHostName)"

		for i in "${LOGS[@]}" ; do
			echo "	${i}"  >> "${lHostName}-$(date +"%Y-%m-%dT%H:%M:%SZ")-LOG.csv"
		done
	fi
}

function cBrowsers {

	mkdir -p "Browsers"
		
	echo -e "\nGathering browser data"
	echo "-------------------------------------------------------------------------------"

	# Full Disk Access must be granted for this to work.

	if [ -d "/Applications/Safari.app" ] ; then

		mkdir -p "Browsers/Safari"
		cp ~/Library/Safari/History.db ~/Library/Safari/Downloads.plist Browsers/Safari/

	fi

	if [ -d "/Applications/Google Chrome.app" ] ; then

		if pgrep "Google Chrome" ; then
			killall "Google Chrome"
		fi
		
		mkdir -p "Browsers/Chrome"
		cp "$HOME/Library/Application Support/Google/Chrome/Default/History" Browsers/Chrome/
	fi

	if [ -d "/Applications/Firefox.app" ] ; then

		mkdir -p "Browsers/Firefox"
		find "$HOME/Library/Application Support/Firefox/Profiles/" -name 'places.sqlite' -exec cp -R {} Browsers/Firefox \;
	fi

}

function cLaunch {

	local tempDirectory

	echo -e "\nGathering launch information"
	echo "-------------------------------------------------------------------------------"

	if ! mkdir -p "Launch" ; then
		echo "${FAIL}[-]${NC} Couldn't make Launch directory. Exiting..."
		exit 1
	fi

	echo -e "\nGathering cronjobs"
	echo "-------------------------------------------------------------------------------"

	mkdir -p "Launch/Cron"

	tempDirectory="Launch/Cron"

	while IFS=$'\n' read -r user; do

		if  [[ -f /usr/lib/cron/tabs/"${user}" ]] ; then
			mkdir -p "${tempDirectory}/${user}"

			#shellcheck disable=SC2024
			if sudo cat /usr/lib/cron/tabs/"${user}" >> "${tempDirectory}/${user}"/cron.txt ; then
				log "INFO" "cron: ${user} copied."
			else
				log "WARN" "cron: ${user} not copied."
			fi
		fi

		USERS+=("${user}")

	done < <(dscl . list /Users | grep -v '_')

	
	echo -e "\nGathering Launch Agents and Daemons"
	echo "-------------------------------------------------------------------------------"

	declare -a LaunchPaths=("/Library/LaunchAgents" "/Library/LaunchDaemons" "/System/Library/LaunchAgents" "/System/Library/LaunchDaemons")
	tempDirectory="Launch/macOSLaunchAgents"

	for path in "${LaunchPaths[@]}" ; do
		mkdir -p "${tempDirectory}/${path}"
	
		find "$path" -type f ! -name "com.apple.*" -exec cp -R {} "${tempDirectory}/${path}" \; 
	done

	set +e

	echo -e "\nGathering User Launch Agents and Daemons"
	echo "-------------------------------------------------------------------------------"

	tempDirectory="Launch/userLaunchAgents"
	for user in "${USERS[@]}" ; do 

		mkdir -p "${tempDirectory}/${user}"
		cp /Users/"${user}"/Library/LaunchAgents/* "${tempDirectory}/${user}" 2>/dev/null

	done

	set -e
}


function cFiles {

	echo -e "\nGathering permissions and hash of user files"
	echo "-------------------------------------------------------------------------------"

	if [ "${SKIP}" == "false" ] ; then

		for user in "${USERS[@]}" ; do

			if ! [[ "${user}" == "root" || "${user}" ==  "nobody" || "${user}" == "daemon" ]] ; then
				mkdir -p "Files/${user}"
				find "/Users/${user}" -type f -exec stat -n -t "%d/%m/%y %R" -f "%Sp |  %Sa | %SB | " {} \; -exec shasum -a 256 {}  \; >> "Files/${user}/${user}-files.txt"
			fi
			
		done

		echo -e "\nGathering .fsventsd Folder"
		echo "-------------------------------------------------------------------------------"

		mkdir "FSEvents"

		if ! sudo cp -r /.fseventsd/ FSEvents/ ; then
			echo "${WARN}[!]${NC} Couldn't copy fseventsd folder..." 
		fi
	else
		echo "SKIP set. Skipping...."
	fi
		
	
}

function cSysdiagnose {

	echo -e "\nRunning sysdiagnose. This will take a while."
	echo "-------------------------------------------------------------------------------"
	sudo sysdiagnose -f . -b

}

function cUser {

	if ! mkdir "User" ; then
		echo "${FAIL}[-]${NC} Couldn't make User directory. Exiting..."
		exit 1
	fi

	echo -e "\nGathering user information"
	echo "-------------------------------------------------------------------------------"

	set +e

	while IFS=$'\n' read -r users; do

		mkdir User/"${users}" 2> /dev/null

		dscacheutil -q user -a name "${users}" >> User/users.txt
		homeDir=$(eval echo ~"${users}")

		find "${homeDir}" -name ".*" -exec cp {} User/"${users}" \; 2> /dev/null

		# Currently this needs to be run without sudo...
		if [[ -f "${homeDir}".zsh_history ]] ; then
			history -En > User/"${users}"/zsh_history
		fi

	done < <(dscl . list /Users | grep -v '_')

	set -e

	echo -e "\nGathering login history"
	echo "-------------------------------------------------------------------------------"
	
	echo -e "\n$(last)" >> User/last.txt

	echo -e "\nGathering sudo users"
	echo "-------------------------------------------------------------------------------"
	cp /etc/sudoers User/
	

}

function cApplication {

	declare -a APPLICATIONS

	#CHECK SIGNING STATUS OF APPS

	if ! mkdir "Applications" ; then
		echo "${FAIL}[-]${NC} Couldn't make disk directory. Exiting..."
		exit 1
	fi	

	echo -e "\nGathering Application Data"
	echo "-------------------------------------------------------------------------------"

	echo -e "$(system_profiler SPApplicationsDataType | grep -E -B6 "Location:" | grep -E '^    .*:' | grep -E -A3 -B2 'Obtained from: Identified Developer|Obtained from: Unknown')" >> Applications/Applications.txt

	echo -e "\nGathering Install History"
	echo "-------------------------------------------------------------------------------"
	echo -e "$(system_profiler SPInstallHistoryDataType)" >> Applications/InstallHistory.txt

	echo -e "\nGathering Currently Running Processes"
	echo "-------------------------------------------------------------------------------"

	# shellcheck disable=SC2009
	echo -e "$(ps xa -o 'user, pid, command' | grep -v '_' | tr -s ' ' | cut -d ' ' -f 1- | sort)" >> Applications/processes.txt

	echo -e "\nChecking Signing and Notarization of Apps"
	echo "-------------------------------------------------------------------------------"

	while IFS=$'\n' read -r line ; do

		APPLICATIONS+=("${line}")

	done < <(system_profiler SPApplicationsDataType | grep 'Location: ' | awk -F 'Location: ' ' { print $2 } ')

	for app in "${APPLICATIONS[@]}" ; do

		if ! [ "${app}" == "/Applications/Xcode.app" ] ; then
			if codesign --verify --deep --strict "${app}" 2>&1 ; then
				if stapler validate "${app}" >/dev/null 2>&1 ; then
					echo "${app}" >> Applications/notarized.txt
				else
					echo "${app}" >> Applications/signed.txt
				fi
			else
				echo "${app}" >> Applications/notsigned.txt
			fi
		else
			echo "SKIPPING XCODE"
		fi
	done

	echo -e "\nGenerating Hash of Non-Apple Application Executables"
	echo "-------------------------------------------------------------------------------"

	local directory

	while IFS=$'\n' read -r app; do

		directory=$(echo "${app}" | awk -F ': ' ' { print $NF } ' )
		# echo -e "\n ${directory}" >> Applications/hash.txt

		find "${directory}" -type f -perm +0111 -exec shasum {} \; >> Applications/hash.txt		

	done < <(system_profiler SPApplicationsDataType | grep -E -B6 "Location:" | grep -E '^    .*:' | grep -E -A3 -B2 'Obtained from: Identified Developer|Obtained from: Unknown' | grep 'Location:' | grep -E -v '/Library/Image Capture|/Library/Printers')
}

function cSecurity {

	echo -e "\nGathering System Security Data"
	echo "-------------------------------------------------------------------------------"

	if csrutil status | grep -q 'enabled' ; then
		status="enabled"
	else
		status="disabled"
	fi

	echo " - System Integrity Protection: ${status}" >> security.txt

	if /usr/libexec/firmwarecheckers/eficheck/eficheck \
		--integrity-check | grep -q 'No changes' ; then
	 	status="passed"
	 else
	 	status="failed"
	fi

	echo " - EFI Integrity: ${status}" >> security.txt

	mrt="$(softwareupdate --history --all | grep MRT | awk -F "softwareupdated" 'NR > 1 { exit }; 1' | awk -F " " ' { print $2 } ')"

	echo " - MRT Version: ${mrt}" >> security.txt

	if [[ "$(defaults read /Library/Preferences/com.apple.alf globalstate)" -ge 1 ]] ; then
		status="enabled"
	else 
		status="disabled"
	fi


	echo " - macOS Firewall: ${status}" >> security.txt

	if [[ "$(defaults read /Library/Preferences/com.apple.alf stealthenabled)" -ge 1 ]] ; then
		status="enabled"
	else 
		status="disabled"
	fi

	echo " - macOS Stealth Firewall: ${status}" >> security.txt

	# shellcheck disable=SC2012
	date="$(ls -l /System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist | awk -F " " ' { print $6" "$7" "$8 } ')"

	echo " - XProtect last updated: ${date}" >> security.txt

	echo " - Current macOS Version: $(sw_vers -productVersion)" >> security.txt

	if ! softwareupdate -l | grep -q 'No new' ; then
		status="Up-to-date"
	else
		status="Update available"
	fi

	echo " - macOS update status: ${status}" >> security.txt

	if fdesetup status | grep "On" > /dev/null ; then
		status="enabled"
	else
		status="disabled"
	fi

	echo " - Filevault: ${status}" >> security.txt

	if sudo firmwarepasswd -check | grep -q 'Yes' ; then
		status="enabled"
	else
		status="disabled"
	fi

	echo " - Firmware Password: ${status}" >> security.txt

}

function cSystemInfo {

	echo -e "\nGathering system info"
	echo "-------------------------------------------------------------------------------"	

	{ 
		echo -e "Date: \t$(date)"
		echo -e "\nHostname: \t$(hostname)"
		echo -e "\nSoftware Version: \t$(sw_vers -productVersion)"
		echo -e "\nKernel Info: \t$(uname -a)"
		echo -e "\nSystem Uptime: \t$(uptime)"
		echo -e "\nSerial Number: \t$(system_profiler SPHardwareDataType | grep "Serial Number" | awk -F ':' ' { print $NF } ')" 
	} >> systeminfo.txt

}

function cNetworkInfo {

	echo -e "\nGathering network info"
	echo "-------------------------------------------------------------------------------"
	echo -e "\n$(ifconfig)" >> Network/ifconfig.txt
	echo -e "\n$(arp -a)" >> Network/arp.txt
	lsof -i | tr -s ' ' >> Network/lsof.txt
}

function cDiskInfo {

	if ! mkdir "disk" ; then
		echo "${FAIL}[-]${NC} Couldn't make disk directory. Exiting..."
		exit 1
	fi

	echo -e "\nGathering disk info"
	echo "-------------------------------------------------------------------------------"
	echo -e "\n$(diskutil list)" >> disk/diskutil.txt
	echo -e "\n$(df -h)" >> disk/df.txt
}

function collect {

	local lHostName
	
	echo "${INFO}[*]${NC} Started collection...Writing to collect.log"
	log "INFO" "Started Collection"

	lHostName="$(scutil --get LocalHostName)"


	echo -e "\nStarting tcpdump"
	echo "-------------------------------------------------------------------------------"

	mkdir "Network"

	tcpdump -n -U -P >> "Network/${lHostName}".pcapng & 
	sleep 5

	# cSysdiagnose
	cSystemInfo
	cDiskInfo
	cNetworkInfo
	cSecurity
	cApplication
	cUser
	cLaunch
	cBrowsers
	cFiles

	echo -e "\nEnding tcpdump"
	echo "-------------------------------------------------------------------------------"

	if ! pkill -15 "tcpdump" ; then
		sleep 5
		pkill "tcpdump"
	fi

}

# Save data to a local disk image
function localDisk {
	
	local directory
	local passphrase
	local dirSize

		# Generate random directory name
		directory="$HOME/$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')"

		echo "${INFO}[*]${NC} Creating directory at ${directory}"
		log "INFO" "Started 'disk'"

		if [[ ! -e "$directory" ]] ; then
			mkdir "$directory" && cd "$directory"

			lHostName="$(scutil --get LocalHostName)"

			collect "${SKIP}"

			echo "${INFO}[*]${NC} Collected data. Creating disk image..."
			log "INFO" "Creating disk image"

			# Create disk image based on the size of the generated directory
			dirSize=$(du -sk . | tr -cd '[:digit:]')
			dirSize=$((dirSize + 102400))

			# Generate random passphrase
			passphrase=$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')

			echo "${INFO}[*]${NC} Performing shasum of files..."
				log "INFO" "Shasum started"

				# Perform shasum of all generated files. Allows for integrity check.
				if find . -type f -exec shasum -a 256 '{}' \; >> "${lHostName}"-shasum.txt ; then
					echo "${PASS}[+]${NC} shasum completed. Stored in: ${lHostName}-shasum.txt"
					log "PASS" "shasum completed"
				else
					echo "${WARN}[!]${NC} shasum failed. Continuing..."
					log "WARNING" "shasum failed"
				fi

			# Create disk image
			if echo -n "${passphrase}" | hdiutil create -fs apfs -size "${dirSize}"kb -format UDRW -stdinpass -encryption AES-128 -srcfolder "${directory}" "${directory}/output".dmg  ; then
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

				collect "${SKIP}"

				echo "${INFO}[*]${NC} Performing shasum of files..."
				log "INFO" "Shasum started"

				if find . -type f -exec shasum -a 256 '{}' \; >> "${lHostName}"-shasum.txt ; then
					echo "${PASS}[+]${NC} Shasum complete. Stored in: ${lHostName}-shasum.txt"
					log "PASS" "Shasum completed"
				else
					echo "${WARN}[!]${NC} Shasum failed. Continuing..."
					log "WARNING" "Shasum failed"
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


	if [ ! "${ipPort}" == "none" ] && [[ "${ipPort}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\:[0-9]{1,5}$ ]] ; then

		ip=$(echo "${ipPort}" | awk -F ":" ' { print $1 } ')
		port=$(echo "${ipPort}" | awk -F ":" ' { print $2 } ')
		# IFS="."

		# read -r -a ipArray <<< "$ip"

		# if [[ ${ipArray[0]} -le 255 ]] &&  [[ ${ipArray[1]} -le 255 ]] && [[ ${ipArray[2]} -le 255 ]] && [[ ${ipArray[3]} -le 255 ]]; then
		# 	echo "YAY2"
		# 	log "INFO" "IP Address valid"
		# else
		# 	echo "${FAIL}[-]${NC} Please provide a valid IP address and port. Exiting..."

		# 	log "ERROR" "IP Address not valid"
		# 	exit 1
		# fi

		IFS=$'\n'

		directory="$HOME/$(head -c24 < /dev/urandom | base64 | tr -cd '[:alnum:]')"

		echo "${INFO}[*]${NC} Creating temporary directory at ${directory}"
		log "INFO" "Temporary directory created at ${directory}"
	
		if ! [[ -d "${directory}" ]] ; then
			mkdir "${directory}" && cd "${directory}"
		else
			echo "${FAIL}[-]${NC} Failed to create directory. Exiting..."
			log "ERROR" "Couldn't create directory ${directory}"
			exit 1
		fi

		collect "${SKIP}"

		# Compress files
		echo "${INFO}[*]${NC} Performing Shasum of files..."
		log "INFO" "Shasum started"

		lHostName="$(scutil --get LocalHostName)"

		if find . -type f -exec shasum -a 256 '{}' \; >> "${lHostName}"-shasum.txt ; then
			echo "${PASS}[+]${NC} Shasum complete. Stored in: ${lHostName}-shasum.txt"
			log "INFO" "Shasum completed"
		else
			echo "${WARN}[!]${NC} Shasum failed. Continuing..."
			log "WARN" "Shasum failed"
		fi

		if tar cvf output.tar ./* > /dev/null 2>&1 ; then
			
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
		
		echo "${INFO}[*]${NC} Starting nc transfer to ${ipPort}..."
		log "INFO" "netcat started"

		echo "${INFO}[*]${NC} Waiting on connection..."

		if nc -n "${ip}" "${port}" -w 30 < "${lHostName}.tar" ; then
			echo "${PASS}[+]${NC} Successfully transferred data. Remember passphrase: ${passphrase}"
			log "INFO" "Data transferred successfully"
		fi
	else
		echo "${FAIL}[-]${NC} Please provide an IP address. Exiting..."
		log "ERROR" "No IP address provided"
		exit 1
	fi
}

function check_sudo {
	log "INFO" "Checking sudo permissions"

	echo "${INFO}[*]${NC} Checking sudo permissions..."

	if [ "$EUID" -ne 0 ] ; then
		echo "${FAIL}[-]${NC} Please run with sudo..."
 	 	exit 1
	fi

}

function main {

	check_sudo

	SKIP=${2:-"false"}

	while getopts ":hdnu" opt; do
		case ${opt} in
			h ) usage
				;;
			d ) disk; 
				;;
			n ) local ip=${2:-"none"}; network "${ip}"
				;;
			u ) local disk=${2:-"none"}; usb "${disk}"
				;;
			* ) usage
				;;
		esac
	done


	log "FINISHED" "Successfully completed ?"

	# Add statement to check the number of arguments and if equal to 1 then call usage.
}

main "$@"