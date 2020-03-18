#!/usr/bin/env bash

set -euo pipefail
# -e exit if any command returns non-zero status code
# -u prevent using undefined variables
# -o pipefail force pipelines to fail on first non-zero status code

FAIL=$(echo -en '\033[01;31m')
PASS=$(echo -en '\033[01;32m')
NC=$(echo -en '\033[0m')
INFO=$(echo -en '\033[01;35m')
WARN=$(echo -en '\033[1;33m')

IFS=$'\n'

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

	echo "Updating Homebrew..."
	brew update >> /dev/null

	echo "Upgrading Homebrew..."
	brew upgrade >> /dev/null

	echo "Installing tools using brewfile..."
	brew bundle --file Brewfile


}

function main {
	true
}

main "$@"