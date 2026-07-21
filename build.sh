#!/bin/sh
#
# $Id: $
#
# Compile and prep the Mac DNS Sleuth application

set -e
umask 022

action=usage
appdir=
appname="Mac DNS Sleuth.app"
buildtop=
ostarget=
partial=true
workdir=

error() { echo "$@" >&2; exit 1; }

usage()
{
	echo "\
Compile and prep the Mac DNS Sleuth application
build.sh [-abchmpu]

  -a Build the python helper application (takes a long time)
  -b Build the whole app
  -c Clean up the app binaries and start over
  -h Help
  -m Build the main Swift app
  -p Prepare the application for running
  -t target macOS version for swiftc compiler (eg: arm64-apple-macos14.0)
  -u Build the application tree and copy in resources
"
	exit 1
}

check_python()
{
	python3 -c '
import sys
print("Python", ".".join(map(str, sys.version_info[:3])))
sys.exit(0 if sys.version_info >= (3, 10) else 1)
'
}


# try to set the architecture type
get_arch()
{
	arch=$(uname -m) ||
		error "Couldn't get system architecture type"
	echo "${arch}"-apple-macos14.0
}

# use a work directory
setup_workenv()
{
	buildtop=$(
		CDPATH=
		cd "$(dirname "$0")" ||
			exit 1
		pwd
	) ||
		error "Couldn't determine build directory"

	workdir="${buildtop}/mac-dns-sleuth-work"
	appdir="${buildtop}/${appname}"
	mkdir -p "${workdir}" || error "Couldn't mkdir $workdir"
}

# paranoid deletions
safe_remove()
{
	[ -e "$1" ] || return 0
	case "$1" in
	  "$workdir"|"$appdir")
		;;
	  *)
		error "Refusing to remove unexpected path: $1"
		;;
	esac

	rm -rf -- "${1}.old"
	mv "$1" "${1}.old"
	rm -rf -- "${1}.old"
}

# clean up the work dir
cleanup()
{
	# handle -c
	if [ $# -eq 0 ]
	then
		cleanup "$workdir"
		cleanup "$appdir"
		return
	fi

	case "$1" in
	  "$workdir")
			safe_remove "$workdir"
			mkdir -p "$workdir"
			;;
	  "$appdir")
			safe_remove "$appdir"
			;;
	  *)
			error "cleanup: unexpected target: $1"
			;;
	esac
}

# build the main executable
build_main()
{
	[ -n "$ostarget" ] || ostarget=$(get_arch)
	echo "Building main application for $ostarget"
	(
		$partial && cleanup "$workdir"
		cd "$workdir" || error "Cannot enter $workdir"
		command -v swiftc >/dev/null 2>&1 ||
			error "swiftc not found"

		swiftc \
			-target "$ostarget" \
			"${buildtop}/mac-dns-sleuth.swift" \
			-framework Cocoa \
			-framework SwiftUI \
			-o mac-dns-sleuth
	)
}

# build the python helper executable
build_helper()
{
	echo "Building python helper application"
	pyver=$(check_python) ||
		error "Python 3.10 required by found: $pyver"
	(
		$partial && cleanup "$workdir"
		cd "$workdir" || error "Cannot enter $workdir"
		command -v python3 >/dev/null 2>&1 ||
			error "python3 not found"

		python3 -m venv venv
		. venv/bin/activate
		python -m pip install --upgrade pip
		python -m pip install -r "${buildtop}/requirements.txt"
		python -m nuitka \
			--standalone \
			--onefile \
			--include-package=cryptography \
			--include-package-data=checkdmarc \
			--include-package-data=publicsuffixlist \
			--include-distribution-metadata=cryptography \
			"${buildtop}/mac-dns-sleuth-helper.py"
	)
}

# construct a macOS app structure and populate it
update_resources()
{
	r="${buildtop}/resources"

	helperbin="${workdir}/mac-dns-sleuth-helper.bin"
	mainbin="${workdir}/mac-dns-sleuth"

	echo "Building app structure"
	mkdir -p "${appdir}/Contents/MacOS"
	mkdir -p "${appdir}/Contents/Resources"

	[ -f "$helperbin" ] ||
		error "$helperbin does not exist; build failed?"
	cp "$helperbin"  "${appdir}/Contents/Resources/"

	[ -f "$mainbin" ] ||
		error "$mainbin does not exist; build failed?"
	cp "$mainbin" "${appdir}/Contents/MacOS/"

	echo "Updating application resource data"
	cp "${r}/Info.plist" "${appdir}/Contents/"
	cp "${r}/mac-dns-sleuth.icns" "${r}"/*.md "${r}"/*.png \
		"${appdir}/Contents/Resources/"
}

# codesign the app and remove quarantine flags
prep_app()
{
	echo "Preparing $appname for distribution"

	command -v codesign >/dev/null 2>&1 ||
		error "codesign not found"
	command -v xattr >/dev/null 2>&1 ||
		error "xattr not found"

	[ -d "${appdir}" ] || error "$appname does not exist; build failed?"
	touch "$appdir"
	codesign --force --sign - \
		"${appdir}/Contents/Resources/mac-dns-sleuth-helper.bin"
	codesign --force --sign - \
		"${appdir}/Contents/MacOS/mac-dns-sleuth"
        codesign --force --sign - "$appdir"

	# Make sure the application isn't quarantined
	xattr -rd com.apple.quarantine "$appdir"
}

# complete build steps
build_mac_dns_sleuth()
{
	echo "Building $appname"

	cleanup "$workdir"
	cleanup "${buildtop}/${appname}"

	build_helper
	build_main
	update_resources
	prep_app

	echo "Mac DNS Sleuth is ready."
}

while getopts 'abchmpt:u' opts
do
	case $opts in
	  a) action=build_helper;;
	  b)	partial=false
		action=build_mac_dns_sleuth
		;;
	  c) action=cleanup;;
	  h) action=usage;;
	  m) action=build_main;;
	  p) action=prep_app;;
          t) ostarget=$OPTARG;;
	  u) action=update_resources;;
	  *) action=usage;;
	esac
done

shift $((OPTIND - 1))
[ "$OPTIND" -gt 1 ] || usage

case "$action" in
  usage) ;;
  *) setup_workenv ;;
esac

$action
