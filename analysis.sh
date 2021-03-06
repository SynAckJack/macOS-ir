#!/usr/bin/env bash
# macOS-ir/analysis.sh 

# Analyse collected data from executign collect.sh.
# Produce PDF's stored in /tmp/Report/hostname-date/

set -euo pipefail

# Colours for output
FAIL=$(echo -en '\033[01;31m[-]\033[0m')
PASS=$(echo -en '\033[01;32m[+]\033[0m')
INFO=$(echo -en '\033[01;35m[*]\033[0m')
WARN=$(echo -en '\033[1;33m[!]\033[0m')

# Internal Field Seperator
IFS=$'\n'

# Log the functions that have been executed, including the return status

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

# Verify integrity of received files. 
function check_hash {

	echo -e "\n${INFO} Checking shasum of files"
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
				# As the file that contains the checksum can't be hashed, this will always fail
				echo "Checksum file failed. This is due to the checksum file not containing a hash for itself. Don't worry about it..."	
				# TODO: Add an IF to check for this file and handle it
			fi
		done
	else
		echo "All files passed checksum."
	fi
}

# Parse data for some files that are specifically formatted.
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

# Create the main PDF html format. This will later be converted to a PDF
function create_main_html {

		cat << EOF > "${reportDirectory}/${hostname}.html"
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
	<h2>$(date -u +"%Y-%m-%dT%H:%M:%SZ")    (All dates and times are UTC throughout)</h2>

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

# Create another html file. This is used for data that isn't needed in the main html or would be too large to include
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
	<h2>$(date -u +"%Y-%m-%dT%H:%M:%SZ")</h2>

	<div class="pagebreak"></div>
EOF

}

# Parse the system information
function analyse_sysinfo {
	
	echo -e "\n${INFO} Analysing sysinfo"
	echo "-------------------------------------------------------------------------------"

	read_file "systeminfo.txt"

	dDate="${LINES[0]}"
	dHostName="${LINES[1]}"
	dMacOSVersion="${LINES[2]}"
	dKernelVersion="${LINES[3]}"
	dUptime="${LINES[4]}"
	dSerialNumber="${LINES[5]}"


# Write the data to the respective html file
cat << EOF >> "${reportDirectory}/${hostname}.html"
	<h1 id="systeminformation">System Information</h1>
	<br>
		<table>
		  <tr>
		    <td>Host name: </td>
		    <td>${dHostName}</td> 
		  </tr>
		  <tr>
		    <td>Date: </td>
		    <td>${dDate}</td> 
		  </tr>
		  <tr>
		    <td>macOS Version: </td>
		    <td>${dMacOSVersion}</td> 
		  </tr>
		  <tr>
		    <td>Kernel Version: </td>
		    <td>${dKernelVersion}</td> 
		  </tr>
		  <tr>
		    <td>Uptime: </td>
		    <td>${dUptime}</td> 
		  </tr>
		  <tr>
		    <td>Serial Number: </td>
		    <td>${dSerialNumber}</td> 
		  </tr>
		</table>

		<br><br><br>

EOF

}

# Parse the data from the security file
function analyse_security {

	unset "LINES[@]"

	echo -e "\n${INFO} Analysing security"
	echo "-------------------------------------------------------------------------------"

	read_file "security.txt"

	dSIP="${LINES[0]}"
	dEFI="${LINES[1]}"
	dMRT="${LINES[2]}"
	dFirewall="${LINES[3]}"
	dStealthFirewall="${LINES[4]}"
	dXProtect="${LINES[5]}"
	dUpdateStatus="${LINES[7]}"
	dFileVault="${LINES[8]}"
	dFirmwarePassword="${LINES[9]}"

	# Check the values received from the file
	# Underline and CAPS if the value is unexpected, such as a feature being disabled
	if [[ "${dSIP}" == " disabled" ]] ; then
		dSIP="<u> DISABLED</u>"
	fi

	if [[ "${dEFI}" == " failed" ]] ; then
		dEFI="<u> FAILED</u>"
	fi

	if [[ "${dFirewall}" == " disabled" ]] ; then
		dFirewall="<u> DISABLED</u>"
	fi

	if [[ "${dStealthFirewall}" == " disabled" ]] ; then
		dStealthFirewall="<u> DISABLED</u>"
	fi

	if [[ "${dUpdateStatus}" == " Update Available" ]] ; then
		dUpdateStatus="<u> UPDATE AVAILABLE</u>"
	fi

	if [[ "${dFileVault}" == " disabled" ]] ; then
		dFileVault="<u> DISABLED</u>"
	fi

	cat << EOF >> "${reportDirectory}/${hostname}.html"

	<h1 id="securityinformation">Security Information</h1>
	<br>
		<table>
		  <tr>
		    <td>System Integrity Protection: </td>
		    <td>${dSIP}</td> 
		  </tr>
		  <tr>
		    <td>EFI Integrity: </td>
		    <td>${dEFI}</td> 
		  </tr>
		  <tr>
		    <td>Malware Removal Tool Version: </td>
		    <td>${dMRT}</td> 
		  </tr>
		  <tr>
		    <td>Firewall: </td>
		    <td>${dFirewall}</td> 
		  </tr>
		  <tr>
		    <td>Stealth Firewall: </td>
		    <td>${dStealthFirewall}</td> 
		  </tr>
		  <tr>
		    <td>XProtect Version: </td>
		    <td>${dXProtect}</td> 
		  </tr>
		  <tr>
		    <td>Update Status: </td>
		    <td>${dUpdateStatus}</td> 
		  </tr>
		  <tr>
		    <td>FileVault Status: </td>
		    <td>${dFileVault}</td> 
		  </tr>
		  <tr>
		    <td>Firmware Password: </td>
		    <td>${dFirmwarePassword}</td> 
		  </tr>
		</table>
	<br><br><br>
EOF

}

function analyse_applications {

	echo -e "\n${INFO} Analysing applications"
	echo "-------------------------------------------------------------------------------"


cat << EOF >> "${reportDirectory}/${hostname}.html"


	<h1 id="applicationinformation">Application Information</h1>
	<br>
		<table>
EOF
	unset "LINES[@]"

	if [ -e "Applications/Applications.txt" ] ; then

		sed 's/--//g' < Applications/Applications.txt > /tmp/Applications.txt

		while IFS=$'       ' read -r line; do

			LINES+=("${line}")

		done < /tmp/Applications.txt
		TMPFILES+=("/tmp/Applications.txt")
	
	fi

	for line in "${LINES[@]}" ; do

		title=$(echo "${line}" | awk -F ':' ' { print $1 } ') >> /dev/null
		value=$(echo "${line}" | cut -d':' -f2-) >> /dev/null

		if [ -n "${title}" ] || [ -n "${value}" ] ; then

			if [ "${title}" == "Location" ] ; then
				{
					echo "<tr>"
					echo "<td>${title}: </td>"
					echo "<td>${value}</td>"
					echo "</tr>"
					echo "<tr><td>------------------------------</td><td>--------------------------------------------------------------------------------------------------------------------------------------------------------</td></tr>"
				}	 >> "${reportDirectory}/${hostname}.html"
			else 
				{
					echo "<tr>"
					echo "<td>${title}: </td>"
					if [[ "${value}" == " Unknown" ]] ; then
						echo "<td><u>${value}</u></td>"
					else 
						echo "<td>${value}</td>"
					fi
					echo "</tr>"
				}  >> "${reportDirectory}/${hostname}.html"
			fi
		fi


	done 

	cat << EOF >> "${reportDirectory}/${hostname}.html"

		</table>
		<br><br><br>
EOF
}

# Print the install history. 
# Not much handling needs done here as it was filtered at time of collection
function analyse_install_history {

	echo -e "\n${INFO} Analysing install history"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}/${hostname}.html"


	<h1 id="installhistory">Install History</h1>
	<br>
		<table>
EOF
	
	while IFS=$'\n' read -r line ; do

		echo "${line}<br>" >> "${reportDirectory}/${hostname}.html"

	done < <((grep -B3 -A1 -E "Source: 3rd Party" | sed 's/--//g') < Applications/InstallHistory.txt)

echo "</table><br><br><br>"  >> "${reportDirectory}/${hostname}.html"

}

# Print the hash of the executables
function print_hash {

	echo -e "\n${INFO} Printing Executable Hashes"
	echo "-------------------------------------------------------------------------------"

	create_secondary_html "Hash of Executables"

	cat << EOF >> "${reportDirectory}/Hash of Executables.html"


	<h1 id="hashes">Hashes of Executables</h1>
	<br>
		<table>
		<th align=left>Hashes (SHA-256)</th><th align=left>Executable Path</th>
EOF
	
	while IFS=$'\n' read -r line ; do
		# Seperate the filepath and hash so that they can be spaced correctly
		tempLine=$(echo "${line}" | awk -F '  ' ' { print $1 } ')
		echo "<tr>" >> "${reportDirectory}/Hash of Executables.html"
		echo "<td>${tempLine}</td>" >> "${reportDirectory}/Hash of Executables.html"

		tempLine=$(echo "${line}" | awk -F '  ' ' { print $2 } ')
		echo "<td>${tempLine}</td>" >> "${reportDirectory}/Hash of Executables.html"
		echo "<tr>" >> "${reportDirectory}/Hash of Executables.html"

	done < Applications/hash.txt



cat << EOF >> "${reportDirectory}/Hash of Executables.html"

		</table>
		<br><br><br>
EOF
}

# Print a list of Applications and their signature status
# Print only unsigned .apps to the main PDF. Otherwise print to a secondary file
function print_signing {

	echo -e "\n${INFO} Printing Non-Signed Applications"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}/${hostname}.html"


	<h1 id="signing">Non-Signed Applications</h1>
	<br>

EOF

	if [ -f Applications/notsigned.txt ] ; then

		echo "<i>Note: The following applications are classed as 'Not Signed'. This can be due to them not being signed or failing the requirements for signing.</i><br><br>" >> "${reportDirectory}/${hostname}.html" 
		while IFS=$'\n' read -r line ; do

			echo "${line}<br>" >> "${reportDirectory}/${hostname}.html" 

		done < <(cat Applications/notsigned.txt)

	else
		echo "All Applications are signed!<br>" >> "${reportDirectory}/${hostname}.html" 
	fi

	echo "<br><br><i>A list of all Applications and their signing status can be found in 'Application Signing Status.pdf'.</i><br>" >> "${reportDirectory}/${hostname}.html"

	if [ -f Applications/notsigned.txt ] && [ -f Applications/signed.txt ] ; then
	
		create_secondary_html "Application Signing Status"

		if [ -f /Applications/notarized.txt ] ; then

			{
				echo "<h1>Notarized Applications</h1><br>"
				echo "<i>Note: Notarized Applications are checked for malware by Apple. These can (typically) be inherently trusted due to this.</i><br><br>"
			}  >> "${reportDirectory}/Application Signing Status.html"

			while IFS=$'\n' read -r line ; do

				echo "${line}<br>" >> "${reportDirectory}/Application Signing Status.html"

			done < <(cat Applications/notarized.txt)

		fi

		{
			echo "<br><br><br>"
			echo "<h1>Signed Applications</h1><br>"
			echo "<i>Note: Although Applications have been signed, they can still be malicious. A certificate can be revoked if Apple deem the Application as malicious, however it can still be distributed and installed.</i><br><br>"
		} >> "${reportDirectory}/Application Signing Status.html"

		while IFS=$'\n' read -r line ; do

			echo "${line}<br>" >> "${reportDirectory}/Application Signing Status.html"

		done < <(cat Applications/signed.txt)

		{
			echo "<br><br><br>"
			echo "<h1>Non-Signed Applications</h1><br>"
			echo "<i>Note: These Applications may either be not signed at all or are signed but do not fall under Apple's requirements.<br>
			More information on these requirements can be found at developer.apple.com</i><br><br>"
		}  >> "${reportDirectory}/Application Signing Status.html"

		while IFS=$'\n' read -r line ; do

			echo "${line}<br>" >> "${reportDirectory}/Application Signing Status.html"

		done < <(cat Applications/notsigned.txt)
	fi

}

# Extract data from the history and download files for each browser
function analyse_browser {

	echo -e "\n${INFO} Analysing Browsers"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}/${hostname}.html" 


	<h1 id="browsers">Browsers</h1>
	<br>
	<p><i>Browser history can be found in "Browser History.pdf"</i></p>
	<br>

EOF

	create_secondary_html "Browser History"
	cat << EOF >> "${reportDirectory}/Browser History.html"


	<h1> Browser History </h1>
	<br>

EOF

	if [ -d Browsers/Safari/ ] ; then

		# To make life easier, convert the Safari Download.plist to xml
		# It makes searching easier
		if plutil -convert xml1 Browsers/Safari/Downloads.plist -o /tmp/Downloads.xml  ; then
			TMPFILES+=("/tmp/Downloads.xml")

			echo "<h1 id='browsers/safari'>Safari - Downloads</h1>"  >> "${reportDirectory}/${hostname}.html" 	
			echo "<table>"   >> "${reportDirectory}/${hostname}.html" 

			while IFS=$'\n' read -r line ; do

				tempLine=$(echo "${line}" | awk -F '<date>|</date>' ' { print $2 } ')
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download Date</td></tr>"  >> "${reportDirectory}/${hostname}.html"
					echo "<tr><td>${tempLine}</td></tr>" >> "${reportDirectory}/${hostname}.html"
				fi

				tempLine=$(echo "${line}" | awk -F '<string>|</string>' ' { print $2 } ')
				if [ -n "${tempLine}" ] ; then
					{
						echo "<tr><td>Download URL</td></tr>"
						echo "<tr><td>${tempLine}</td></tr>"
						echo "<tr></tr>" 
					} >> "${reportDirectory}/${hostname}.html"
				fi

			done < <((grep -A1 -E 'DownloadEntryURL|DownloadEntryDateAddedKey') < /tmp/Downloads.xml)

			echo "</table>" >> "${reportDirectory}/${hostname}.html" 
		else
			echo "Can't analyse Safari Downloads"
		fi

		# Database files must be copied to the local disk if transferred using a disk image/usb as these are read-only.
		# Sqlite3 requires r/w access to query so they are copied to /tmp
		if cp -R Browsers/Safari/History.db /tmp/ ; then
			TMPFILES+=("/tmp/History.db")

			{
				echo "<h1>Safari - History</h1>"
				echo "<table>"  
				echo "<th align=left>ID</th><th align=left>Date</th><th align=left>URL</th>"
			}  >> "${reportDirectory}/Browser History.html"

			# Query History.db to get history item, id and timestamp
			tempdb=$(sqlite3 /tmp/History.db "SELECT DISTINCT l.ID, l.url, r.visit_time FROM history_items l INNER JOIN history_visits r ON r.history_item = l.ID ORDER BY l.ID;" | sed 's/\|/ /g')

			db=$(echo -e "${tempdb}\n")

			prevID=0
			
			if ! IFS=$' ' read -rd '' -a y <<< "$db" ; then
				while IFS=$'\n' read -r line ; do

					id=$(echo "${line}" | awk -F " " ' { print $1 } ')

					# Monitor the ID to prevent duplicate entries
					if ! [[ "$prevID" -eq "$id" ]] ; then					
						time=$(echo "${line}" | awk -F " " ' { print $3 } ' | cut -f1 -d".")
						# Convert the time from Cocoa Core Data
						# see: https://www.epochconverter.com/coredata
						time=$((time+978307200))
						date=$(date -r "${time}" +"%Y-%m-%dT%H:%M:%SZ")
						url=$(echo "${line}" | awk -F " " ' { print $2 } ')

						echo "<tr><td>${id}</td><td>${date}</td><td>${url}</td></tr>" >> "${reportDirectory}/Browser History.html"
					fi

					prevID="${id}"

				done < <(echo "${y[@]}")
			fi

			echo "</table><br>"   >> "${reportDirectory}/Browser History.html"
	
		else
			echo "Can't analyse Safari history."
		fi

	else
		echo "Can't analyse Safari."
	fi

	if [ -d Browsers/Chrome/ ] ; then

		if cp -R Browsers/Chrome/History /tmp/ ; then

			TMPFILES+=("/tmp/History" "/tmp/History.db-shm" "/tmp/History.db-wal")

			echo "<h1 id='browsers/chrome'>Chrome - Downloads</h1>"  >> "${reportDirectory}/${hostname}.html" 		
			echo "<table>"   >> "${reportDirectory}/${hostname}.html" 

			while IFS=$'\n' read -r line ; do

				tempLine=$(echo "${line}" | awk -F ' ' ' { print $1" "$2" "$3" "$4" "$5} ')
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download Date</td></tr>"  >> "${reportDirectory}/${hostname}.html"
					echo "<tr><td>${tempLine}</td></tr>" >> "${reportDirectory}/${hostname}.html"
				fi

				tempLine=$(echo "${line}" | awk -F ' ' ' { print $7 } ')
				if [ -n "${tempLine}" ] ; then
					{
						echo "<tr><td>Download URL</td></tr>"
						echo "<tr><td>${tempLine}</td></tr>"
						echo "<tr></tr>" 
					} >> "${reportDirectory}/${hostname}.html"
				fi

			done < <((sqlite3 /tmp/History "SELECT last_modified, referrer  FROM downloads;" | sed 's/\|/ /g'))

			echo "</table>" >> "${reportDirectory}/${hostname}.html" 

			{
				echo "<h1>Chrome - History</h1>"
				echo "<table>"  
				echo "<th align=left>ID</th><th align=left>Date</th><th align=left>URL</th>"
			}  >> "${reportDirectory}/Browser History.html"

			tempdb=$(sqlite3 /tmp/History "SELECT id, url, last_visit_time FROM urls;")

			db=$(echo -e "${tempdb}\n")

			prevID=0
			
			if ! IFS=$' ' read -rd '' -a y <<< "$db" ; then
				while IFS=$'\n' read -r line ; do

					id=$(echo "${line}" | awk -F "|" ' { print $1 } ')

					# Monitor ID to prevent trying to parse a newline character or create duplicate entries
					if ! [[ "${prevID}" -eq "${id}" ]] || [[ "${id}" == "\n" ]] ; then					
						time=$(echo "${line}" | awk -F "|" ' { print $3 } ' | cut -f1 -d".")
						# Convert time from WebKit/Chrome timestamp
						# see: https://timothycomeau.com/writing/chrome-history and https://www.epochconverter.com/webkit
						time=$(((time/1000000)-11644473600))
						date=$(date -r "${time}" +"%Y-%m-%dT%H:%M:%SZ")
						url=$(echo "${line}" | awk -F "|" ' { print $2 } ')

						echo "<tr><td>${id}</td><td>${date}</td><td>${url}</td></tr>" >> "${reportDirectory}/Browser History.html"
					fi

					prevID="${id}"

				done < <(echo "${y[@]}")
			fi	
			echo "</table><br>"   >> "${reportDirectory}/Browser History.html"
		else

		echo "Can't analyse Chrome"		
		fi
	fi

	if [ -d Browsers/Firefox/ ] ; then

		if cp -R Browsers/Firefox/places.sqlite /tmp/ ; then

			TMPFILES+=("/tmp/places.sqlite" "/tmp/places.sqlite-shm" "/tmp/places.sqlite-wal")

			echo "<h1 id='browsers/firefox'>Firefox - Downloads</h1>"  >> "${reportDirectory}/${hostname}.html" 		
			echo "<table>"   >> "${reportDirectory}/${hostname}.html" 

			while IFS=$'\n' read -r line ; do

				tempLine=$(echo "${line}" | awk -F '|' ' { print $1} ')
				time=$((time/1000000))
				date=$(date -r "${time}" +"%Y-%m-%dT%H:%M:%SZ" )
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download Date</td></tr>"  >> "${reportDirectory}/${hostname}.html"
					echo "<tr><td>${date}</td></tr>" >> "${reportDirectory}/${hostname}.html"
				fi

				tempLine=$(echo "${line}" | awk -F '|' ' { print $2 } ')
				if [ -n "${tempLine}" ] ; then
					{
						echo "<tr><td>Download URL</td></tr>"
						echo "<tr><td>${tempLine}</td></tr>"
						echo "<tr></tr>" 
					} >> "${reportDirectory}/${hostname}.html"
				fi

			done < <((sqlite3 /tmp/places.sqlite "SELECT moz_annos.dateAdded,  moz_places.url FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id AND anno_attribute_id = 1;"))

			{
				echo "</table>"
				echo "<h1>Firefox - History</h1>"
				echo "<table>"  
				echo "<th align=left>ID</th><th align=left>Date</th><th align=left>URL</th>"
			}  >> "${reportDirectory}/Browser History.html"

			tempdb=$(sqlite3 /tmp/places.sqlite "SELECT r.id, l.visit_date, r.url FROM moz_historyvisits l INNER JOIN moz_places r ON l.place_id = r.id;")

			db=$(echo -e "${tempdb}\n")
			
			if ! IFS=$' ' read -rd '' -a y <<< "$db" ; then
				while IFS=$'\n' read -r line ; do

						id=$(echo "${line}" | awk -F "|" ' { print $1 } ')
						time=$(echo "${line}" | awk -F "|" ' { print $2 } ')
						time=$((time/1000000))
						date=$(date -r "${time}" +"%Y-%m-%dT%H:%M:%SZ")
						url=$(echo "${line}" | awk -F "|" ' { print $3 } ')

						echo "<tr><td>${id}</td><td>${date}</td><td>${url}</td></tr>" >> "${reportDirectory}/Browser History.html"

				done < <(echo "${y[@]}")
			fi	

			echo "</table><br><br><br>"   >> "${reportDirectory}/${hostname}.html" 		
		else
			echo "Can't analyse Firefox."
		fi
	fi

}

function print_disk {

	echo -e "\n${INFO} Printing Disk Information"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}/${hostname}.html" 

	<h1 id="disk">Disk Information</h1>
EOF

	if [ -e disk/diskutil.txt ] ; then
		echo "<pre>" >> "${reportDirectory}/${hostname}.html" 
		while IFS=$'\r' read -r line ; do
			echo "${line}" | expand -t4 >> "${reportDirectory}/${hostname}.html" 
		done < <(cat disk/diskutil.txt)
		echo "</pre>" >> "${reportDirectory}/${hostname}.html" 

		
	fi

	echo "<br><br><br>"   >> "${reportDirectory}/${hostname}.html" 		

}

# Print a list of files and their hashes to secondary PDF
function print_files {

	echo -e "\n${INFO} Printing File Information"
	echo "-------------------------------------------------------------------------------"

	if [ -d Files/ ] ; then
		

	cat << EOF > "${reportDirectory}"/FileHashes.html

	<!DOCTYPE html>

	<html>

	<head>
	    <title>File Information</title>
	</head>

	<style>

		@media print{@page {size: landscape}}

		html * {
			font-size: 1em !important;
			color: #000 !important;
			font-family: Arial !important;
		}

		h1 { 
			font-size: 2em !important;
			font-weight: bold !important;
		}

	</style>

	<body>

	<h1>File Information</h1>
	<br>
	<table>
	<th>Permissions</th><th>Last Modified</th><th>Created</th><th>Hash</th><th>Path</th>

EOF


		while IFS=$'\n' read -r file ; do
			
			while IFS="$" read -r line ; do

				{
					echo "${line} " | awk -F '|' ' { print "<tr><td>" $1 "</td><td>" $2 "</td><td>" $3 "</td>" } '
					temp=$(echo "${line} " | awk -F '|' ' { print $4 } ')
					echo "${temp}" | awk -F ' /' ' { print "<td>" $1 "</td>"} '
					echo "${temp}" | awk -F ' /' ' { print "<td>" $2 "</td></tr>"} '
				}  >> "${reportDirectory}"/FileHashes.html

			done < <(cat -e "$file")

		done < <(find ./Files/ -type f -name "*.txt")

cat << EOF >> "${reportDirectory}"/FileHashes.html

			</table>
		</body>
	</html>
EOF
	else 
		echo "'Files' directory does not exist. Skipping..."
			return 0
	fi
}

function analyse_cron {

	echo -e "\n${INFO} Printing Cron Jobs"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}/${hostname}.html" 


	<h1 id="cron">Cron Jobs</h1>
	<br>

EOF

	for job in Launch/Cron/* ; do 
	
		if [ -f "${job}/cron.txt" ] ; then
			{
				echo "<p><b>${job} Cron Jobs: </b></p>"
				echo "<pre>"
				sudo cat "${job}/cron.txt"
			}  >> "${reportDirectory}/${hostname}.html" 
		fi
		echo "</pre>" >> "${reportDirectory}/${hostname}.html" 
		echo "<br>"  >> "${reportDirectory}/${hostname}.html" 
	done

	echo "<br><br><br>" >> "${reportDirectory}/${hostname}.html" 	
}

# Print Launch Agents/ Daemons
function analyse_launch_agents {

	echo -e "\n${INFO} Printing Launch Agents"
	echo "-------------------------------------------------------------------------------"

	create_secondary_html "Launch Agents"
	cat << EOF >> "${reportDirectory}/Launch Agents.html"


	<h1> Launch Agents </h1>
	<br>

EOF

	cat << EOF >> "${reportDirectory}/${hostname}.html" 


	<h1 id="launchagents">Launch Agents</h1>
	<br>
	<i>The following contains a list of all Launch Agents for the device. Where the path begins with a username, the full path is /Users/[username]/Library/LaunchAgents/[Launch Agent]. The contents of the Launch Agents can be found in the PDF Launch Agents.pdf </i><br><br>

EOF
	mkdir -p /tmp/launch/

	TMPFILES+=("/tmp/launch")

	while IFS=$'\n' read -r path ; do 

		tempPath="$(echo "${path}" | cut -d'/' -f 3-)" 

		echo "${tempPath}<br>" >> "${reportDirectory}/${hostname}.html"	

		{	
			echo "<b>${tempPath}</b><br>"
			echo "<pre>"
			(sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4) < "${path}"
			echo "</pre>"
			echo "<br>"
		} >> "${reportDirectory}/Launch Agents.html" 

	done < <(find Launch -name "*.plist" )

	echo "<br><br><br>"   >> "${reportDirectory}/${hostname}.html" 		
}

function print_networking {

	echo -e "\n${INFO} Printing Network Information"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}/${hostname}.html" 


	<h1 id="network">Network Information</h1>
	<br>

EOF

	if [ -f Network/arp.txt ] ; then

		echo "<b id='network/arp'>ARP Table</b><br>" >> "${reportDirectory}/${hostname}.html" 

		while IFS=$'\n' read -r line ; do 

			{	
				echo "<pre>"
				echo "${line}"
			} >> "${reportDirectory}/${hostname}.html" 

		done < <(cat Network/arp.txt)

		echo "</pre><br>" >> "${reportDirectory}/${hostname}.html" 
	fi

	if [ -f Network/ifconfig.txt ] ; then

		echo "<b  id='network/ifconfig'>IFCONFIG Output</b><br>" >> "${reportDirectory}/${hostname}.html" 

		while IFS=$'\n' read -r line ; do 

			{
				echo "<pre>"
				echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4
			} >> "${reportDirectory}/${hostname}.html" 

		done < <(cat Network/ifconfig.txt)

		echo "</pre><br>" >> "${reportDirectory}/${hostname}.html" 
	fi

	# Create database to show outgoing network connections
	if [ -f Network/lsof.txt ] ; then

		echo "<b  id='network/connections'>Network Connections</b><br>" >> "${reportDirectory}/${hostname}.html"  

		# Create table to store process data
		if sqlite3 /tmp/tmp.db "CREATE TABLE process(id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, pid INTEGER, command TEXT);" ; then

			TMPFILES+=("/tmp/tmp.db")

			# Create table to store lsof data
			if sqlite3 /tmp/tmp.db "CREATE TABLE lsof(id INTEGER PRIMARY KEY AUTOINCREMENT, command TEXT,  pid INTEGER, user TEXT, node TEXT, name TEXT);" ; then

				while IFS=$'\n' read -r line; do

					# Extract and insert process data into database
					user=$(echo "${line}" | cut -d ' ' -f 1)
					pid=$(echo "${line}" | cut -d ' ' -f 2)
					cmd=$(echo "${line}" | cut -d ' ' -f 3-)

					sqlite3 /tmp/tmp.db  "INSERT INTO process (user, pid, command) VALUES (\"${user}\", \"${pid}\", \"${cmd}\");"
						
				done < <(cat Applications/processes.txt)

				while IFS=$'\n' read -r line; do
					
					# Extract and insert lsof data into database
					user=$(echo "${line}" | cut -d ' ' -f 3)
					pid=$(echo "${line}" | cut -d ' ' -f 2)
					cmd=$(echo "${line}" | cut -d ' ' -f 1)
					node=$(echo "${line}" | cut -d ' ' -f 8)
					name=$(echo "${line}" | cut -d ' ' -f 9)

					sqlite3 /tmp/tmp.db  "INSERT INTO lsof (command, pid, user, node, name) VALUES (\"${cmd}\", \"${pid}\", \"${user}\", \"${node}\", \"${name}\");"

				done < <(tr -s ' ' < Network/lsof.txt  )

				# Query constructed database to select data to show network connections and the processes that created them
				db=$(sqlite3 /tmp/tmp.db "SELECT l.user, l.pid, r.node, r.name, l.command FROM process l INNER JOIN lsof r ON l.pid = r.pid;")

				if ! IFS=$' ' read -rd '' -a y <<< "$db" ; then

					{	
						echo "Command paths have been shortened for system paths: "
						echo "S/L/F/WK.f/ -> System/Library/Frameworks/WebKit.framework/"
						echo "S/L/PF/WK.f/ -> System/Library/PrivateFrameworks/WebKit.framework/"
						echo "<table>"
						echo "<tr><th align=left>User</th><th align=left>PID</th><th align=left>Type</th><th align=left>Connection</th><th align=left>Command</th></tr>"
					}  >> "${reportDirectory}/${hostname}.html" 

					# Parse the network connections data
					while IFS=$'\n' read -r line ; do

						user=$(echo "${line}" | awk -F "|" ' { print $1 } ')
						pid=$(echo "${line}" | awk -F "|" ' { print $2 } ')
						node=$(echo "${line}" | awk -F "|" ' { print $3 } ')
						name=$(echo "${line}" | awk -F "|" ' { print $4 } ' | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g')

						# Shorten full paths to try and prevent them from going off page
						command=$(echo "${line}" | awk -F "|" ' { print $5 } ' | sed 's;/System/Library/Frameworks/WebKit.framework;S/L/F/WK.f;g' | sed 's;/System/Library/PrivateFrameworks/WebKit.framework;S/L/PF/WK.f;g' | sed 's;/System/Library/PrivateFrameworks;S/L/PF;g')

						echo "<tr><td>${user}</td><td>${pid}</td><td>${node}</td><td>${name}</td><td>${command}</td></tr>" >> "${reportDirectory}/${hostname}.html" 

					done < <(echo "${y[@]}")

					echo "</table>"  >> "${reportDirectory}/${hostname}.html" 
				fi
			fi
		fi
	fi

	echo "<br><br><br>"   >> "${reportDirectory}/${hostname}.html" 
}

# Print user information
function print_user {

	echo -e "\n${INFO} Printing User Information"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}/${hostname}.html"


	<h1 id="user">User</h1>
	<br>

EOF
	
	declare -a SUDOCOMMANDS
	
	if [ -d User ] ; then 
		if [ -f User/users.txt ]; then
		
			echo "<b id='user/users'>Users</b><br>" >> "${reportDirectory}/${hostname}.html"

			echo "<pre>" >> "${reportDirectory}/${hostname}.html"
			while IFS=$'\n' read -r line ; do 

				echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4 >> "${reportDirectory}/${hostname}.html"

			done < <(cat User/users.txt)

			echo "</pre><br>" >> "${reportDirectory}/${hostname}.html"
		fi

		if [ -f User/sudoers ]; then
		
			echo "<b id='user/sudoers'>Sudoers</b><br>" >> "${reportDirectory}/${hostname}.html"

			echo "<pre>" >> "${reportDirectory}/${hostname}.html"

			while IFS=$'\n' read -r line ; do 

				echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4 >> "${reportDirectory}/${hostname}.html"

			done < <(cat User/sudoers)

			echo "</pre><br>" >> "${reportDirectory}/${hostname}.html"
		fi

		if [ -f User/users.txt ]; then
			
			echo "<b id='user/last'>Last Output</b><br>" >> "${reportDirectory}/${hostname}.html"

			echo "<pre>" >> "${reportDirectory}/${hostname}.html"

			while IFS=$'\n' read -r line ; do 

				echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4 >> "${reportDirectory}/${hostname}.html"

			done < <(cat User/last.txt)

			echo "</pre><br>" >> "${reportDirectory}/${hostname}.html"

		fi

		{
			echo "<h1 id='commands'>Command History</h1><br>"
			echo "<i>The following contains a list of commands ran by the root user. There is also a list of other command run by other users containing 'sudo'.<br>" 
			echo "A list of all commands run by each user can be found in 'Command History.pdf'.</i><br><br>"
		} >> "${reportDirectory}/${hostname}.html"

		# Print shell history for each user. Supports bash and zsh currently
		for dir in User/*/ ; do

			if ! [[ "${dir}" == "User/daemon/"  ||  "${dir}" == "User/nobody/" ]] ; then
				user=$(echo "${dir}" | awk -F '/' ' { print $2 } ')

				# Print root command history
				# Seperate from other users as this is more of a security risk and is printed to the main PDF
				if [[ "${dir}" == "User/root/" ]] ; then

					# Print rootbash history
					if [ -f "${dir}/.bash_history" ] ; then

						echo "<b> ${user} - Bash History </b> " >> "${reportDirectory}/${hostname}.html"
						while IFS=$'\n' read -r line ; do 

							{
								echo "<pre>"
								echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4
								echo "</pre>"
							} >> "${reportDirectory}/${hostname}.html"

						done < <(cat "${dir}/.bash_history")

						echo "</pre><br>" >> "${reportDirectory}/${hostname}.html"
					fi

					# Print root zsh history
					if [ -f "${dir}/.zsh_history" ] ; then

						echo "<b>${user} - Zsh History </b>">> "${reportDirectory}/${hostname}.html"
						while IFS=$'\n' read -r line ; do 

							tmp=$(echo "${line}" | cut -d ':' -f 2 | tr -d '[:blank:]')

							if [[ ${tmp} =~ ^[0-9]+$ ]] ; then
								
								cmdDate=$(date -r "${tmp}" +"%Y-%m-%dT%H:%M:%SZ" )
								command=$(echo "${line}" | cut -d ';' -f 2 | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g')

								{
									echo "<pre>"
									echo "${cmdDate}  --  ${command}"
									echo "</pre>"
								} >> "${reportDirectory}/${hostname}.html"
							else
								{
									echo "<pre>"
									echo "${line}"
									echo "</pre>"
								} >> "${reportDirectory}/${hostname}.html"

							fi
							
						done < <(cat "${dir}/.zsh_history")
						echo "</pre><br>" >> "${reportDirectory}/${hostname}.html"
					fi
				else

					# Print the remainder of the user command history to seperate PDF
					if [ -f "${dir}/.bash_history" ] ; then

						if ! [ -f "${reportDirectory}/Command History.html" ] ; then
							create_secondary_html "Command History"
						fi

						echo "<b> ${user} - Bash History </b> " >> "${reportDirectory}/Command History.html"
						while IFS=$'\n' read -r line ; do 

							# Filter for commands with 'sudo'
							if echo "${line}" | grep -c 'sudo' >> /dev/null; then
									# sudo found. Print to main PDF file.
									SUDOCOMMANDS+=("${line}")
							fi

							{
								echo "<pre>"
								echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4
								echo "</pre>"
							} >> "${reportDirectory}/Command History.html"

						done < <(cat "${dir}/.bash_history")

						write_sudo_commands "${user}" "bash"

						echo "</pre><br>" >> "${reportDirectory}/Command History.html"
					fi

					if [ -f "${dir}/.zsh_history" ] ; then

						echo "<b>${user} - Zsh History </b>" >> "${reportDirectory}/Command History.html"
						while IFS=$'\n' read -r line ; do 

							tmp=$(echo "${line}" | cut -d ':' -f 2 | tr -d '[:blank:]')

							if [[ ${tmp} =~ ^[0-9]+$ ]] ; then
								
								cmdDate=$(date -r "${tmp}" +"%Y-%m-%dT%H:%M:%SZ" )
								command=$(echo "${line}" | cut -d ';' -f 2 | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g')

								if echo "${command}" | grep -c 'sudo'  >> /dev/null ; then

									# sudo found. Print to main PDF file.
									SUDOCOMMANDS+=("${command}")
								fi

								{
									echo "<pre>"
									echo "${cmdDate}  --  ${command}"
									echo "</pre>"
								} >> "${reportDirectory}/Command History.html"
							else
								{
									echo "<pre>"
									echo "${line}"
									echo "</pre>"
								} >> "${reportDirectory}/Command History.html"

							fi
							
						done < <(cat "${dir}/.zsh_history")

						write_sudo_commands "${user}" "Zsh"

						echo "</pre><br>" >> "${reportDirectory}/Command History.html"

					fi
				fi
			fi
		done
	fi

	cat << EOF >> "${reportDirectory}/${hostname}.html"
		</body>
	</html>
EOF
}

# Print sudo commands to main PDF file
function write_sudo_commands {
	
	user="$1"
	shell="$2"

	if [ "${#SUDOCOMMANDS[@]}" -gt 0 ] ; then

		{	
			
			echo "<b>${user} ${shell} Sudo Commands</b><br><br>"
			for c in "${SUDOCOMMANDS[@]}" ; do
				echo "<pre>"
				echo "${c}"
				echo "</pre>"
			done
			echo "<br><br>"
		} >> "${reportDirectory}/${hostname}.html"
	fi
	
	unset "SUDOCOMMANDS[@]"

}

# Extract sysdiagnose
function parse_sysdiagnose {
	
	echo -e "\n${INFO} Parsing sysdiagnose"
	echo "-------------------------------------------------------------------------------"

	if ! mkdir -p "/tmp/sysdiagnose" ; then
		echo "${FAIL} Couldn't make extract directory. Exiting..."
		exit 1
	fi

	TMPFILES+=("/tmp/sysdiagnose")

	archive=$(find . -name "*.tar.gz" | awk -F './' ' { print $NF }' )
	echo "${archive}"

	originaldir=$PWD
	echo "${originaldir}"
	if [[ -n "${archive}" ]] ; then

		if tar -xf "${archive}" -C /tmp/sysdiagnose ; then
			echo "${PASS} Successfully extracted sysdiagnose to /tmp/sysdiagnose..."
			cd /tmp/sysdiagnose/"${archive%.tar.gz}" || exit
		else
			echo "${WARN} Failed to extract sysdiagnose..."
		fi
	else
		echo "${WARN} sysdiagnose not found..."
	fi
}

# Cleanup function.
# Delete any of the temporary files that were copied to /tmp/
function cleanup {

	echo -e "\n${INFO} Performing Cleanup"
	echo "-------------------------------------------------------------------------------"
	set +u

	declare -a TMPFAILED

	for f in "${TMPFILES[@]}" ; do
		if ! rm -rf "${f}" ; then
			TMPFAILED+=("${f}")
		fi
	done

	if [ "${#TMPFAILED[@]}" -gt 0 ] ; then
		echo "The following files/directories could not be deleted from /tmp/"

		for i in "${TMPFAILED[@]}" ; do
			echo "${i}"
		done
	else
		echo "Completed Cleanup. All done."
	fi 

	set -u
}

# Decrypt the data received from netcat 
function decrypt {
	
	local passphrase
	local tarFile

	tarFile=$(find . -name '*.tar' )	

	echo "${INFO} Decrypting .tar file. Please enter passphrase: "
	read -rp 'Passphrase: ' passphrase
 	
 	while [ "${passphrase}" != "q" ] ; do
 		echo "Attempting to decrypt with: ${passphrase}..."

 		if openssl enc -d -aes256 -in "${tarFile}" -pass pass:"${passphrase}" | tar xz  ; then
 			echo "${PASS} Successfully decrypted .tar to directory: ~/output."
 			break
 		else
 			echo "${WARN} Failed to decrypt .tar. Please enter new passphrase or 'q' to exit..."
 			read -rp 'Passphrase: ' passphrase
 		fi
  	done
}

# Receive data over the network using netcat
function network {
	local port
	local passphrase

	echo "${INFO} Checking valid port..."

	port=${1}

	if [[ "${port}" =~ ^[0-9]{1,5} ]] && [[ "${port}" -le 65535 ]] ; then
		
		mkdir -p ~/output && cd ~/output

		echo "${INFO} Connecting to nc on port ${port}..."

		if nc -l "${port}" > received.tar; then
			echo "${PASS} Successfully received data."

			decrypt
		else
			echo "${FAIL} Failed to receive data. Exiting..."
			exit 1
		fi

	else
		echo "${FAIL} Please enter a valid port. Exiting..."
		exit 1
	fi 
}

# Extract the data from a disk image
function localDisk {
	
	local diskName
	local tarFile
	local passphrase

	diskName="$1"

	if [[ "${diskName}" == "none" ]] ; then
		echo "FAIL. Please enter a disk name..."
		exit 1
	fi

	volume=$(echo "$diskName" | awk -F '/' ' { print $(NF-1) }')

	echo "${INFO} Checking disk. Please enter the passphrase..."
	read -rp 'Passphrase: ' passphrase

	if echo -n "${passphrase}" | hdiutil attach "${diskName}" -stdinpass  ; then
		echo "${PASS} Succesfully attached disk."
		cd "/Volumes/${volume}"

		log "PASS" "Disk mounted"
	else
		echo "${FAIL} Incorrect passphrase. Exiting..."
		log "ERROR" "Disk mount failed"
		exit 1
	fi
}

# Extract the data from a usb
function usb {
	
	local usbName
	local tarFile
	local passphrase

	usbName="$1"

	echo "${INFO} Checking USB. Please enter the passphrase..."
	read -rp 'Passphrase: ' passphrase
 
	if diskutil apfs unlockVolume "${usbName}" -passphrase "${passphrase}"; then

		if cd /Volumes/"${usbName}" ; then
			echo "${PASS} USB exists and is available. Locating .tar..."
			mkdir -p ~/output
			if tar -xvf output.tar -C ~/output ; then
				echo "${PASS} .tar extracted to 'output' successfully..."
				cd ~/output
			else
				echo "${WARN} Failed to extract .tar. Exiting..."
				exit 1
			fi	
		else
			echo "${FAIL} Unable to access USB. Exiting..."
			exit 1
		fi
	else
		echo "${FAIL} Incorrect passphrase. Exiting..."
		exit 1
	fi
}

# Convert the reports from html to PDF using wkhtmltopdf
# see: https://wkhtmltopdf.org/
function generate_reports {

	echo -e "\n${INFO} Generating Reports"
	echo "-------------------------------------------------------------------------------"

	cd /tmp/Report || exit

	while IFS=$'\n' read -r line; do

		if [[ "${line}" == "FileHashes.html" ]] ; then
			# Due to the length of some paths, the FileHashes.pdf file is landscape to make room.
			wkhtmltopdf -q -O landscape FileHashes.html FileHashes.pdf
		else 
			wkhtmltopdf -q --print-media-type "${line}" "${line%.html}.pdf"
		fi
		
	done < <(find . -name "*.html")

	echo "Reports generated. These can be found at /tmp/Reports/"
}

# ctrl-c hit. Cleanup.
function control_c {

	echo -e "\n${FAIL}[X]${NC} Ctrl-C hit. Cleaning up..."
	echo "-------------------------------------------------------------------------------"
	cleanup
	exit 1
}

function analysis {

	# Capture ctrl-c keypress and cleanup
	trap control_c SIGINT
	
	hostname=$(find . -name "*-shasum.txt" -print | cut -d '-' -f 1 | tr -d './')

	reportDirectory="/tmp/Report/${hostname} $(date -u +"%Y-%m-%dT%H-%M-%SZ")"

	check_hash

	mkdir -p "${reportDirectory}"

	create_main_html
	analyse_sysinfo
	analyse_security
	analyse_applications
	analyse_install_history
	print_hash
	print_signing
	analyse_browser
	print_disk
	print_files
	analyse_cron
	analyse_launch_agents
	print_networking
	print_user
	parse_sysdiagnose
	generate_reports

	cleanup

	open "${reportDirectory}/"
}

function main {

	trap control_c SIGINT

	while getopts ":hdnui" opt; do
		case ${opt} in
			h ) usage
				;;
			d ) local diskImage=${2:-"none"}; localDisk "${diskImage}"
				analysis
				;;
			n ) local port=${2:-"none"}; network "${port}"
				analysis
				;;
			u ) local disk=${2:-"none"}; usb "${disk}"
				analysis
				;;
			i ) install_tools
				;;
			\?) echo "Invalid option -- $OPTARG "
				usage
				;;
		esac
	done
}

main "$@"
