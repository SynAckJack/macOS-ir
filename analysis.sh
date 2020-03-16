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

function analyse_sysinfo {
	
	echo -e "\n${INFO}[*]${NC} Analysing sysinfo"
	echo "-------------------------------------------------------------------------------"

	read_file "systeminfo.txt"

	dDate="${LINES[0]}"
	dHostName="${LINES[1]}"
	dMacOSVersion="${LINES[2]}"
	dKernelVersion="${LINES[3]}"
	dUptime="${LINES[4]}"


cat << EOF >> "${reportDirectory}"/test.html
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
		</table>

		<br><br><br>

EOF

}

function analyse_security {

	unset "LINES[@]"

	echo -e "\n${INFO}[*]${NC} Analysing security"
	echo "-------------------------------------------------------------------------------"

	read_file "security.txt"

	dSIP="${LINES[0]}"
	dEFI="${LINES[1]}"
	dMRT="${LINES[2]}"
	dFirewall="${LINES[3]}"
	dStealthFirewall="${LINES[4]}"
	dXProtect="${LINES[5]}"
	dUpdateStatus="${LINES[7]}"

	cat << EOF >> "${reportDirectory}"/test.html

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
		</table>
	<br><br><br>
EOF

}

function analyse_applications {

	echo -e "\n${INFO}[*]${NC} Analysing applications"
	echo "-------------------------------------------------------------------------------"


cat << EOF >> "${reportDirectory}"/test.html


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
				}	 >> "${reportDirectory}"/test.html
			else 
				{
					echo "<tr>"
					echo "<td>${title}: </td>"
					echo "<td>${value}</td>"
					echo "</tr>"
				}  >> "${reportDirectory}"/test.html
			fi
		fi


	done 

	cat << EOF >> "${reportDirectory}"/test.html

		</table>
		<br><br><br>
EOF
}

function analyse_install_history {

	echo -e "\n${INFO}[*]${NC} Analysing install history"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}"/test.html


	<h1 id="installhistory">Install History</h1>
	<br>
		<table>
EOF
	
	while IFS=$'\n' read -r line ; do

		echo "${line}<br>" >> "${reportDirectory}"/test.html

	done < <((grep -B3 -A1 -E "Source: 3rd Party" | sed 's/--//g') < Applications/InstallHistory.txt)

echo "</table><br><br><br>"  >> "${reportDirectory}"/test.html

}

function print_hash {

	echo -e "\n${INFO}[*]${NC} Printing Executable Hashes"
	echo "-------------------------------------------------------------------------------"

	create_secondary_html "Hash of Executables"

	cat << EOF >> "${reportDirectory}/Hash of Executables.html"


	<h1 id="hashes">Hashes of Executables</h1>
	<br>
		<table>
		<th align=left>Hashes (SHA-256)</th><th align=left>Executable Path</th>
EOF
	
	while IFS=$'\n' read -r line ; do

		tempLine=$(echo "${line}" | awk -F '  ' ' { print $1 } ')
		echo "<tr>" >> "${reportDirectory}/Hash of Executables.html"
		echo "<td>${tempLine}</td>" >> "${reportDirectory}/Hash of Executables.html"
		# echo "<tr>" >> "${reportDirectory}"/test.html

		tempLine=$(echo "${line}" | awk -F '  ' ' { print $2 } ')
		echo "<td>${tempLine}</td>" >> "${reportDirectory}/Hash of Executables.html"
		echo "<tr>" >> "${reportDirectory}/Hash of Executables.html"

	done < Applications/hash.txt



cat << EOF >> "${reportDirectory}/Hash of Executables.html"

		</table>
		<br><br><br>
EOF
}

function print_signing {

	echo -e "\n${INFO}[*]${NC} Printing Non-Signed Applications"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}"/test.html


	<h1 id="signing">Non-Signed Applications</h1>
	<br>

EOF

	if [ -f ~/Github/macos-ir/Applications/notsigned.txt ] ; then

		echo "<i>Note: The following applications are classed as 'Not Signed'. This can be due to them not being signed or failing the requirements for signing.</i><br><br>" >> "${reportDirectory}"/test.html 
		while IFS=$'\n' read -r line ; do

			echo "${line}<br>" >> "${reportDirectory}"/test.html 

		done < <(cat ~/Github/macos-ir/Applications/notsigned.txt)

	else
		echo "All Applications are signed!<br>" >> "${reportDirectory}"/test.html 
	fi

	echo "<br><br><i>A list of all Applications and their signing status can be found in 'Application Signing Status.pdf'.</i><br>" >> "${reportDirectory}"/test.html

	if [ -f ~/Github/macos-ir/Applications/notsigned.txt ] && [ -f ~/Github/macos-ir/Applications/signed.txt ] && [ -f ~/Github/macos-ir/Applications/notarized.txt ] ; then
	
		create_secondary_html "Application Signing Status"

		{
			echo "<h1>Notarized Applications</h1><br>"
			echo "<i>Note: Notarized Applications are checked for malware by Apple. These can (typically) be inherently trusted due to this.</i><br>"
		}  >> "${reportDirectory}/Application Signing Status.html"

		while IFS=$'\n' read -r line ; do

			echo "${line}<br>" >> "${reportDirectory}/Application Signing Status.html"

		done < <(cat ~/Github/macos-ir/Applications/notarized.txt)

		{
			echo "<br><br><br>"
			echo "<h1>Signed Applications</h1><br>"
			echo "<i>Note: Although Applications have been signed, they can still be malicious. A certificate can be revoked if Apple deem the Application as malicious, however it can still be distributed and installed.</i><br>"
		} >> "${reportDirectory}/Application Signing Status.html"

		while IFS=$'\n' read -r line ; do

			echo "${line}<br>" >> "${reportDirectory}/Application Signing Status.html"

		done < <(cat ~/Github/macos-ir/Applications/signed.txt)

		{
			echo "<br><br><br>"
			echo "<h1>Non-Signed Applications</h1><br>"
		}  >> "${reportDirectory}/Application Signing Status.html"

		while IFS=$'\n' read -r line ; do

			echo "${line}<br>" >> "${reportDirectory}/Application Signing Status.html"

		done < <(cat ~/Github/macos-ir/Applications/notsigned.txt)
	fi

}

function analyse_browser {

	echo -e "\n${INFO}[*]${NC} Analysing Browsers"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}"/test.html


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

		if plutil -convert xml1 Browsers/Safari/Downloads.plist -o /tmp/Downloads.xml  ; then
			TMPFILES+=("/tmp/Downloads.xml")

			echo "<h1 id='browsers/safari'>Safari - Downloads</h1>"  >> "${reportDirectory}"/test.html		
			echo "<table>"   >> "${reportDirectory}"/test.html

			while IFS=$'\n' read -r line ; do

				tempLine=$(echo "${line}" | awk -F '<date>|</date>' ' { print $2 } ')
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download Date</td></tr>"  >> "${reportDirectory}"/test.html
					echo "<tr><td>${tempLine}</td></tr>" >> "${reportDirectory}"/test.html
				fi
				# echo "<tr>" >> "${reportDirectory}"/test.html|

				tempLine=$(echo "${line}" | awk -F '<string>|</string>' ' { print $2 } ')
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download URL</td></tr>"  >> "${reportDirectory}"/test.html
					echo "<tr><td>${tempLine}</td></tr>" >> "${reportDirectory}"/test.html
				fi

			done < <((grep -A1 -E 'DownloadEntryURL|DownloadEntryDateAddedKey') < /tmp/Downloads.xml)

			echo "</table>" >> "${reportDirectory}"/test.html
		else
			echo "Can't analyse Safari Downloads"
		fi

		if cp -R Browsers/Safari/History.db /tmp/ ; then
			TMPFILES+=("/tmp/History.db")

			{
				echo "<h1>Safari - History</h1>"
				echo "<table>"  
				echo "<th align=left>ID</th><th align=left>Date</th><th align=left>URL</th>"
			}  >> "${reportDirectory}/Browser History.html"

			
			tempdb=$(sqlite3 /tmp/History.db "SELECT DISTINCT l.ID, l.url, r.visit_time FROM history_items l INNER JOIN history_visits r ON r.history_item = l.ID ORDER BY l.ID;" | sed 's/\|/ /g')

			db=$(echo -e "${tempdb}\n")

			prevID=0
			
			if ! IFS=$' ' read -rd '' -a y <<< "$db" ; then
				while IFS=$'\n' read -r line ; do

					id=$(echo "${line}" | awk -F " " ' { print $1 } ')

					if ! [[ "$prevID" -eq "$id" ]] ; then					
						time=$(echo "${line}" | awk -F " " ' { print $3 } ' | cut -f1 -d".")
						time=$((time+978307200))
						date=$(date -r "${time}" '+%d/%m/%Y:%H:%M:%S')
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

			echo "<h1 id='browsers/chrome'>Chrome - Downloads</h1>"  >> "${reportDirectory}"/test.html		
			echo "<table>"   >> "${reportDirectory}"/test.html

			while IFS=$'\n' read -r line ; do

				tempLine=$(echo "${line}" | awk -F ' ' ' { print $1" "$2" "$3" "$4" "$5} ')
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download Date</td></tr>"  >> "${reportDirectory}"/test.html
					echo "<tr><td>${tempLine}</td></tr>" >> "${reportDirectory}"/test.html
				fi
				# echo "<tr>" >> "${reportDirectory}"/test.html|

				tempLine=$(echo "${line}" | awk -F ' ' ' { print $7 } ')
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download URL</td></tr>"  >> "${reportDirectory}"/test.html
					echo "<tr><td>${tempLine}</td></tr>" >> "${reportDirectory}"/test.html
				fi

			done < <((sqlite3 /tmp/History "SELECT last_modified, referrer  FROM downloads;" | sed 's/\|/ /g'))

			echo "</table>" >> "${reportDirectory}"/test.html

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

					if ! [[ "${prevID}" -eq "${id}" ]] || [[ "${id}" == "\n" ]] ; then					
						time=$(echo "${line}" | awk -F "|" ' { print $3 } ' | cut -f1 -d".")
						time=$(((time/1000000)-11644473600))
						date=$(date -r "${time}" '+%d/%m/%Y:%H:%M:%S')
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

			echo "<h1 id='browsers/firefox'>Firefox - Downloads</h1>"  >> "${reportDirectory}"/test.html		
			echo "<table>"   >> "${reportDirectory}"/test.html

			while IFS=$'\n' read -r line ; do

				tempLine=$(echo "${line}" | awk -F '|' ' { print $1} ')
				time=$((time/1000000))
				date=$(date -r "${time}" '+%d/%m/%Y:%H:%M:%S')
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download Date</td></tr>"  >> "${reportDirectory}"/test.html
					echo "<tr><td>${date}</td></tr>" >> "${reportDirectory}"/test.html
				fi
				# echo "<tr>" >> "${reportDirectory}"/test.html|

				tempLine=$(echo "${line}" | awk -F '|' ' { print $2 } ')
				if [ -n "${tempLine}" ] ; then
					echo "<tr><td>Download URL</td></tr>"  >> "${reportDirectory}"/test.html
					echo "<tr><td>${tempLine}</td></tr>" >> "${reportDirectory}"/test.html
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
						date=$(date -r "${time}" '+%d/%m/%Y:%H:%M:%S')
						url=$(echo "${line}" | awk -F "|" ' { print $3 } ')

						echo "<tr><td>${id}</td><td>${date}</td><td>${url}</td></tr>" >> "${reportDirectory}/Browser History.html"

				done < <(echo "${y[@]}")
			fi	

			echo "</table><br><br><br>"   >> "${reportDirectory}"/test.html		
		else
			echo "Can't analyse Firefox."
		fi
	fi

}

function print_disk {

	echo -e "\n${INFO}[*]${NC} Printing Disk Information"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}"/test.html

	<h1 id="disk">Disk Information</h1>
EOF

	if [ -e disk/diskutil.txt ] ; then
		echo "<pre>" >> "${reportDirectory}"/test.html
		while IFS=$'\r' read -r line ; do
			echo "${line}" | expand -t4 >> "${reportDirectory}"/test.html
		done < <(cat disk/diskutil.txt)
		echo "</pre>" >> "${reportDirectory}"/test.html

		
	fi

	echo "<br><br><br>"   >> "${reportDirectory}"/test.html		

}

function print_files {

	echo -e "\n${INFO}[*]${NC} Printing File Information"
	echo "-------------------------------------------------------------------------------"

	cat << EOF > "${reportDirectory}"/files.html

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
			}  >> "${reportDirectory}"/files.html

		done < <(cat -e "$file")

	done < <(find Files -type f -name "*.txt")

cat << EOF >> "${reportDirectory}"/files.html

			</table>
		</body>
	</html>
EOF
}

function analyse_cron {

	echo -e "\n${INFO}[*]${NC} Printing Cron Jobs"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}"/test.html


	<h1 id="cron">Cron Jobs</h1>
	<br>

EOF

	for job in Launch/Cron/* ; do 
	
		if [ -f "${job}/cron.txt" ] ; then
			{
				echo "<p><b>${job} Cron Jobs: </b></p>"
				echo "<pre>"
				sudo cat "${job}/cron.txt"
			}  >> "${reportDirectory}"/test.html
		fi
		echo "</pre>" >> "${reportDirectory}"/test.html
		echo "<br>"  >> "${reportDirectory}"/test.html
	done

	echo "<br><br><br>" >> "${reportDirectory}"/test.html	
}

function analyse_launch_agents {

	echo -e "\n${INFO}[*]${NC} Printing Launch Agents"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}"/test.html


	<h1 id="launchagents">Launch Agents</h1>
	<br>

EOF
	mkdir -p /tmp/launch/

	TMPFILES+=("/tmp/launch")

	while IFS=$'\n' read -r path ; do 

		{
			echo "<b>${path}</b><br>"
			echo "<pre>"
			(sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4) < "${path}"
			echo "</pre>"
			echo "<br>"
		} >> "${reportDirectory}"/test.html

	done < <(find Launch -name "*.plist" -print)

	echo "<br><br><br>"   >> "${reportDirectory}"/test.html		
}

function print_networking {

	echo -e "\n${INFO}[*]${NC} Printing Network Information"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}"/test.html


	<h1 id="network">Network Information</h1>
	<br>

EOF

	if [ -f Network/arp.txt ] ; then

		echo "<b id='network/arp'>ARP Table</b><br>" >> "${reportDirectory}"/test.html

		while IFS=$'\n' read -r line ; do 

			{	
				echo "<pre>"
				echo "${line}"
			} >> "${reportDirectory}"/test.html

		done < <(cat Network/arp.txt)

		echo "</pre><br>" >> "${reportDirectory}"/test.html
	fi

	if [ -f Network/ifconfig.txt ] ; then

		echo "<b  id='network/ifconfig'>IFCONFIG Output</b><br>" >> "${reportDirectory}"/test.html

		while IFS=$'\n' read -r line ; do 

			{
				echo "<pre>"
				echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4
			} >> "${reportDirectory}"/test.html

		done < <(cat Network/ifconfig.txt)

		echo "</pre><br>" >> "${reportDirectory}"/test.html
	fi

	if [ -f Network/lsof.txt ] ; then

		echo "<b  id='network/connections'>Network Connections</b><br>" >> "${reportDirectory}"/test.html 

		if sqlite3 /tmp/tmp.db "CREATE TABLE process(id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, pid INTEGER, command TEXT);" ; then

			TMPFILES+=("/tmp/tmp.db")

			if sqlite3 /tmp/tmp.db "CREATE TABLE lsof(id INTEGER PRIMARY KEY AUTOINCREMENT, command TEXT,  pid INTEGER, user TEXT, node TEXT, name TEXT);" ; then

				while IFS=$'\n' read -r line; do
	
					user=$(echo "${line}" | cut -d ' ' -f 1)
					pid=$(echo "${line}" | cut -d ' ' -f 2)
					cmd=$(echo "${line}" | cut -d ' ' -f 3-)

					# echo "${user}, ${pid}, ${cmd}"

					sqlite3 /tmp/tmp.db  "INSERT INTO process (user, pid, command) VALUES (\"${user}\", \"${pid}\", \"${cmd}\");"
						
				done < <(cat Applications/processes.txt)

				while IFS=$'\n' read -r line; do
						
					user=$(echo "${line}" | cut -d ' ' -f 3)
					pid=$(echo "${line}" | cut -d ' ' -f 2)
					cmd=$(echo "${line}" | cut -d ' ' -f 1)
					node=$(echo "${line}" | cut -d ' ' -f 8)
					name=$(echo "${line}" | cut -d ' ' -f 9)

					sqlite3 /tmp/tmp.db  "INSERT INTO lsof (command, pid, user, node, name) VALUES (\"${cmd}\", \"${pid}\", \"${user}\", \"${node}\", \"${name}\");"

				done < <(tr -s ' ' < Network/lsof.txt  )

				db=$(sqlite3 /tmp/tmp.db "SELECT l.user, l.pid, r.node, r.name, l.command FROM process l INNER JOIN lsof r ON l.pid = r.pid;")

				if ! IFS=$' ' read -rd '' -a y <<< "$db" ; then

					{	
						echo "Command paths have been shortened for system paths: "
						echo "S/L/F/WK.f/ -> System/Library/Frameworks/WebKit.framework/"
						echo "S/L/PF/WK.f/ -> System/Library/PrivateFrameworks/WebKit.framework/"
						echo "<table>"
						echo "<tr><th align=left>User</th><th align=left>PID</th><th align=left>Type</th><th align=left>Connection</th><th align=left>Command</th></tr>"
					}  >> "${reportDirectory}"/test.html

					while IFS=$'\n' read -r line ; do

						user=$(echo "${line}" | awk -F "|" ' { print $1 } ')
						pid=$(echo "${line}" | awk -F "|" ' { print $2 } ')
						node=$(echo "${line}" | awk -F "|" ' { print $3 } ')
						name=$(echo "${line}" | awk -F "|" ' { print $4 } ' | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g')
						command=$(echo "${line}" | awk -F "|" ' { print $5 } ' | sed 's;/System/Library/Frameworks/WebKit.framework;S/L/F/WK.f;g' | sed 's;/System/Library/PrivateFrameworks/WebKit.framework;S/L/PF/WK.f;g' | sed 's;/System/Library/PrivateFrameworks;S/L/PF;g')

						echo "<tr><td>${user}</td><td>${pid}</td><td>${node}</td><td>${name}</td><td>${command}</td></tr>" >> "${reportDirectory}"/test.html

					done < <(echo "${y[@]}")

					echo "</table>"  >> "${reportDirectory}"/test.html
				fi

			
			fi
		fi
	fi

	echo "<br><br><br>"   >> "${reportDirectory}"/test.html
}

function print_user {

	echo -e "\n${INFO}[*]${NC} Printing User Information"
	echo "-------------------------------------------------------------------------------"

	cat << EOF >> "${reportDirectory}"/test.html


	<h1 id="user">User</h1>
	<br>

EOF
	

	if [ -d User ] ; then 
		if [ -f User/users.txt ]; then
		
		echo "<b id='user/users'>Users</b><br>" >> "${reportDirectory}"/test.html

		echo "<pre>" >> "${reportDirectory}"/test.html
		while IFS=$'\n' read -r line ; do 

			echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4 >> "${reportDirectory}"/test.html

		done < <(cat User/users.txt)

		echo "</pre><br>" >> "${reportDirectory}"/test.html
		fi

		if [ -f User/sudoers ]; then
		
		echo "<b id='user/sudoers'>Sudoers</b><br>" >> "${reportDirectory}"/test.html

		echo "<pre>" >> "${reportDirectory}"/test.html

		while IFS=$'\n' read -r line ; do 

			echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4 >> "${reportDirectory}"/test.html

		done < <(cat User/sudoers)

		echo "</pre><br>" >> "${reportDirectory}"/test.html
		fi

		if [ -f User/users.txt ]; then
		
		echo "<b id='user/last'>Last Output</b><br>" >> "${reportDirectory}"/test.html

		echo "<pre>" >> "${reportDirectory}"/test.html

		while IFS=$'\n' read -r line ; do 

			echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4 >> "${reportDirectory}"/test.html

		done < <(cat User/last.txt)

		echo "</pre><br>" >> "${reportDirectory}"/test.html

		fi

		for dir in User/*/ ; do

			if ! [[ "${dir}" == "User/daemon/"  ||  "${dir}" == "User/nobody/" ]] ; then
				user=$(echo "${dir}" | awk -F '/' ' { print $2 } ')
				if [ -f "${dir}/.bash_history" ] ; then

					echo "<b> ${user} - Bash History </b> " >> "${reportDirectory}"/test.html
					while IFS=$'\n' read -r line ; do 

						{
							echo "<pre>"
							echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4
						} >> "${reportDirectory}"/test.html

					done < <(cat "${dir}/.bash_history")

					echo "</pre><br>" >> "${reportDirectory}"/test.html
				fi

				if [ -f "${dir}/.zsh_history" ] ; then

					echo "<b>${user} - Zsh History </b>">> "${reportDirectory}"/test.html
					while IFS=$'\n' read -r line ; do 

						#Need to find a way to convert the time at the beginning
						{
							echo "<pre>"
							echo "${line}" | sed 's/\</\&lt;/g' | sed 's/\>/\&gt;/g' | expand -t4
						} >> "${reportDirectory}"/test.html

					done < <(cat "${dir}/.zsh_history")
					echo "</pre><br>" >> "${reportDirectory}"/test.html
				fi
			fi
		done
	fi

	cat << EOF >> "${reportDirectory}"/files.html
		</body>
	</html>
EOF
}

function parse_sysdiagnose {
	
	echo -e "\n${INFO}[*]${NC} Parsing sysdiagnose"
	echo "-------------------------------------------------------------------------------"

	if ! mkdir -p "/tmp/sysdiagnose" ; then
		echo "${FAIL}[-]${NC} Couldn't make extract directory. Exiting..."
		exit 1
	fi

	TMPFILES+=("/tmp/sysdiagnose")

	archive=$(find . -name "*.tar.gz" | awk -F './' ' { print $NF }' )
	echo "${archive}"

	originaldir=$PWD
	echo "${originaldir}"
	if [[ -n "${archive}" ]] ; then

		if tar -xf "${archive}" -C /tmp/sysdiagnose ; then
			echo "Extracted"
			cd /tmp/sysdiagnose/"${archive%.tar.gz}" || exit
		else
			echo "Failed"
		fi
	else
		echo "SYSDIAGNOSE NOT FOUND"
	fi
}

function cleanup {

	echo -e "\n${INFO}[*]${NC} Performing Cleanup"
	echo "-------------------------------------------------------------------------------"

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

	reportDirectory="/tmp/Report"


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