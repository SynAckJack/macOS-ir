#!/usr/bin/env bash

# set -euo pipefail
# -e exit if any command returns non-zero status code
# -u prevent using undefined variables
# -o pipefail force pipelines to fail on first non-zero status code

FAIL=$(echo -en '\033[01;31m')
PASS=$(echo -en '\033[01;32m')
NC=$(echo -en '\033[0m')
INFO=$(echo -en '\033[01;35m')

function get_app_data {

	echo "${INFO}Gathering a list of Applications...${NC}"
	while IFS=$'\n' read -r app; do 

	    	appleApps+=("${app}");

	done < <(system_profiler SPApplicationsDataType \
	        | grep -E -B3 "Obtained from: Apple" \
			| grep -E '^    .*:' \
			| awk -F ":" ' { print $1 } ' \
			| grep -E -v 'Version|Obtained from' )

	while IFS=$'\n' read -r app; do 

			identifiedDeveloper+=("${app}");

	done < <(system_profiler SPApplicationsDataType \
	        | grep -E -B3 "Obtained from: Identified Developer" \
			| grep -E '^    .*:' \
			| awk -F ":" ' { print $1 } ' \
			| grep -E -v 'Version|Obtained from' )

	while IFS=$'\n' read -r app; do 

			unknown+=("${app}")

	done < <(system_profiler SPApplicationsDataType \
	        | grep -E -B3 "Obtained from: Unknown" \
			| grep -E '^    .*:' \
			| awk -F ":" ' { print $1 } ' \
			| grep -E -v 'Version|Obtained from' )

	echo "${INFO}Gathering a list of Application paths...${NC}"

	while IFS=$'\n' read -r app; do 

			locations+=("${app}")

	done < <(system_profiler SPApplicationsDataType \
	        | grep -E "Location: /*" \
	        | awk -F ':' ' { print $2 } ' \
	        | sed 's/^ *//g')
}

function print_array {

	echo "Applications Retrieved From:" >> Applications.txt
	echo "Apple" >> Applications.txt
	for i in "${appleApps[@]}"; do
  		echo "  ${i}" >> Applications.txt
	done

	echo "Identified Developers" >> Applications.txt

	for i in "${identifiedDeveloper[@]}"; do
  		echo "  ${i}" >> Applications.txt
	done

	echo "Unknown Developers" >> Applications.txt

	for i in "${unknown[@]}"; do
  		echo "  ${i}" >> Applications.txt
	done

		
	}

function check_signature {

	echo "${INFO}Checking signing status of Applications (this may take a while)...${NC}"

	for i in "${locations[@]}"; do
		signature="$(codesign --verify --deep --strict -v "${i}" 2>&1)"

		if echo "${signature}" | grep -q "code object is not signed at all"; then
			notsigned+=("${i}")
		elif echo "${signature}" | grep -q "resource fork, Finder information, or similar detritus not allowed"; then
			resourcefork+=("${i}")
		elif echo "${signature}" | grep -q "satisfies its Designated Requirement"; then
			signed+=("${i}")
		elif echo "${signature}" | grep -q "a sealed resource is missing or invalid"; then

			brokensignature+=("${i}")
		fi
    done
}


function main {

	declare -a appleApps
	declare -a identifiedDeveloper
	declare -a unknown
	declare -a locations

	declare -a signed
	declare -a resourcefork
	declare -a notsigned
	declare -a brokensignature


	get_app_data
	print_array
	check_signature

	local numberfailed
	local numberpassed

	numberfailed=$((${#notsigned[@]} + ${#resourcefork[@]} + ${#brokensignature[@]}))
	numberpassed=${#signed[@]}

	echo "${PASS}Number of Applications signed:${NC} ${numberpassed}"
	echo "${FAIL}Number of Applications failed signature check:${NC} ${numberfailed}"

	if [ ${#notsigned[@]} -gt 0 ]; then
		echo "Not Signed: "  >> Applications.txt
		for i in "${notsigned[@]}" ; do
			echo "	${i}"  >> Applications.txt
		done
	fi

	if [ ${#resourcefork[@]} -gt 0 ]; then
		echo "Resource fork: " >> Applications.txt
		for i in "${resourcefork[@]}" ; do
			echo "	${i}"  >> Applications.txt
		done
	fi

	if [ ${#brokensignature[@]} -gt 0 ]; then
		echo "Broken Signature: " >> Applications.txt
		for i in "${brokensignature[@]}" ; do
			echo "	${i}"  >> Applications.txt
		done
	fi

	if [ ${#signed[@]} -gt 0 ]; then
		echo "Signed: "
		for i in "${signed[@]}" ; do
			echo "	${i}"  >> Applications.txt
		done
	fi
}

main "$@"

