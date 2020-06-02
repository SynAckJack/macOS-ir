#!/usr/bin/env bash

# lint.sh
# 	Execute Shellcheck on shell files of repo
#	Adapted from 0xmachos/mOSL/test
#	https://github.com/0xmachos/mOSL/blob/master/test

set -euo pipefail
# -e exit if any command returns non-zero status code
# -u prevent using undefined variables
# -o pipefail force pipelines to fail on first non-zero status code

IFS=$'\n'

FAIL=$(echo -en '\033[01;31mFAIL\033[0m')
PASS=$(echo -en '\033[01;32mPASS\033[0m')
INFO=$(echo -en '\033[1;33mWARN\033[0m')

ERRORS=()
FILES_LINTED=()

function usage {

	echo -e "usage: ./lint.sh [ -u | -l /path/to/directory/ ]\\n"

    echo -e "-- If no arguments are passed then the current directory is used --\\n\\n"
	echo -e "-u    - Show this message.\\n"
	echo -e "-l    - Used when executing this on a local machine. "

    exit 0
}

function lint {
    # Find .sh files 
    while IFS=$'\n' read -r path ; do

        FILES_LINTED+=("${path}")

        if ! shellcheck "${path}" ; then
            echo "Failed to lint: ${path}"
            ERRORS+=("${path}") 
        fi
    done < <(find "${filePath}" -iname "*.sh")
}

function main {

    filePath="."

    if [ $# -gt 0 ] ; then

        while getopts ":lu" opt ; do
            case "${opt}" in
                l ) 
                    filePath=${2:-"."}
                    if [ "${filePath}" == "." ]; then
                        echo -e "[$FAIL] Directory not provided..."
                        usage
                    else
                        lint
                    fi
                    ;;

                u )
                    usage
                    ;;

                * )
                    usage
                    ;;
            esac
        done
    else
        lint
    fi

    # List files that have been linted
    echo -e "[${INFO}] These files were linted: \n${FILES_LINTED[*]}\n"

    if [ ${#ERRORS[@]} -gt 0 ] ; then
    # Errors exist. Print the files that failed.
        echo -e "[${FAIL}] These files failed linting: \n${ERRORS[*]}"
        exit 1
    else
        # No errors exist. 
        echo -e "[${PASS}] Everything passed!"
        exit 0
    fi
}

main "$@"

