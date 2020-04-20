#!/usr/bin/env bash
#macOS-ir/lint.sh

# Adapted from 0xmachos: https://github.com/0xmachos

set -euo pipefail

FAIL="\\033[1;31mFAIL\\033[0m"
INFO="\\033[1;36mINFO\\033[0m"
PASS="\\033[1;32mPASS\\033[0m"


check_shellcheck () {

	#The below if statemenet correctly identifies if shellcheck is already however will return a non-zero exit code when shellcheck is installed via 'brew'
	if ! [ -x "$(command -v shellcheck)" ]; then 
	   	echo -e "[${INFO}] shellcheck not installed"
		echo -e "[${INFO}] Attempt to install shellcheck using brew"

		#This if statement fails
		# if [[ $(brew install shellcheck &> /dev/null) ]] ; then
		# 	echo -e "[${INFO}] shellcheck installed"
		# else 
		# 	echo -e "[${FAIL}] couldn't install shellcheck"
		# 	echo -e "[${FAIL}] macOS: brew install shellcheck"
		# 	exit 1
		# fi
	fi 
}


lint_shell_files () {

	for f in $(find . -type f -not -iwholename '*.git*' \
				-not -iwholename '*venv*' \
				-not -iwholename '*DS*' \
				| sort -u); do
		# Find all regular files in source directory

		FILES_LINTED+=("${f}")

		if file "${f}" | grep --quiet "shell" ; then
			# Find shell files
			
			if ! shellcheck "${f}" ; then
				# If shellcheck fails add failing file name to array
				echo -e "[${FAIL}] Failed to lint ${f}"
				ERRORS+=("${f}")
			fi
		
			elif file "${f}" | grep --quiet "bash" ; then
			# Find shell files
			# Running file on a script with the shebang "#!/usr/bin/env ..." returns
			# "a /usr/bin/env bash script, ASCII text executable" rather than
			# "Bourne-Again shell script, ASCII text executable"

			if ! shellcheck "${f}" ; then
				# If shellcheck fails add failing file name to array
				echo -e "[${FAIL}] Failed to lint ${f}"
				ERRORS+=("${f}")
			fi
		fi
	done
}


main () {

	ERRORS=()
	FILES_LINTED=()

	check_shellcheck
	lint_shell_files

	if [ ${#ERRORS[@]} -eq 0 ]; then
		# If ERRORS empty then 
		echo -e "[${PASS}] No errors, hooray"
		echo -e "[${PASS}] The files were linted: "
		for l in "${FILES_LINTED[@]}" ; do
  			echo "${l}"
		done

		exit 0
	else
		# If errors print the names of files which failed
		echo -e "[${FAIL}] These files failed linting: ${ERRORS[*]}"
		exit 1
	fi
}

main "$@"
