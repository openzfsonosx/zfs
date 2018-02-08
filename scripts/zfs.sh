#!/bin/bash
#
# A simple script to simply the loading/unloading the ZFS module stack.

basedir="$(dirname $0)"

SCRIPT_COMMON=common.sh
if [ -f "${basedir}/${SCRIPT_COMMON}" ]; then
. "${basedir}/${SCRIPT_COMMON}"
else
echo "Missing helper script ${SCRIPT_COMMON}" && exit 1
fi

PROG=zfs.sh
UNLOAD=

usage() {
cat << EOF
USAGE:
$0 [hvud] [module-options]

DESCRIPTION:
	Load/unload the ZFS module stack.

OPTIONS:
	-h      Show this message
	-v      Verbose
	-u      Unload modules
	-d      Save debug log on unload

MODULE-OPTIONS:
	Must be of the from module="options", for example:

$0 zfs="zfs_prefetch_disable=1"
$0 zfs="zfs_prefetch_disable=1 zfs_mdcomp_disable=1"
$0 spl="spl_debug_mask=0"

EOF
}

while getopts 'hvud' OPTION; do
	case $OPTION in
	h)
		usage
		exit 1
		;;
	v)
		VERBOSE=1
		;;
	u)
		UNLOAD=1
		;;
	d)
		DUMP_LOG=1
		;;
	?)
		usage
		exit
		;;
	esac
done

kill_zed() {
	if [ -f "$ZED_PIDFILE" ]; then
		PID=$(cat "$ZED_PIDFILE")
		kill "$PID"
	fi
}

check_modules() {
	LOADED_MODULES=""
	MISSING_MODULES=""

	for KMOD in $KMOD_SPL $KMOD_SPLAT $KMOD_ZAVL $KMOD_ZNVPAIR \
	    $KMOD_ZUNICODE $KMOD_ZCOMMON $KMOD_ZLUA $KMOD_ICP $KMOD_ZFS; do
		NAME=$(basename "$KMOD" .ko)

		if lsmod | grep -E -q "^${NAME}"; then
			LOADED_MODULES="$LOADED_MODULES\t$NAME\n"
		fi

		if ! modinfo "$KMOD" >/dev/null 2>&1; then
			MISSING_MODULES="$MISSING_MODULES\t${KMOD}\n"
		fi
	done

	if [ -n "$LOADED_MODULES" ]; then
		printf "Unload the kernel modules by running '%s -u':\n" "$PROG"
		printf "%b" "$LOADED_MODULES"
		exit 1
	fi

	if [ -n "$MISSING_MODULES" ]; then
		printf "The following kernel modules can not be found:\n"
		printf "%b" "$MISSING_MODULES"
		exit 1
	fi

	return 0
}

load_module() {
	KMOD=$1

	FILE=$(modinfo "$KMOD" | awk '/^filename:/ {print $2}')
	VERSION=$(modinfo "$KMOD" | awk '/^version:/ {print $2}')

	if [ "$VERBOSE" = "yes" ]; then
		echo "Loading: $FILE ($VERSION)"
	fi

	$LDMOD "$KMOD" >/dev/null 2>&1
	# shellcheck disable=SC2181
	if [ $? -ne 0 ]; then
		echo "Failed to load $KMOD"
		return 1
	fi

	return 0
}

load_modules() {
	mkdir -p /etc/zfs

	if modinfo "$KMOD_ZLIB_DEFLATE" >/dev/null 2>&1; then
		modprobe "$KMOD_ZLIB_DEFLATE" >/dev/null 2>&1
	fi

	if modinfo "$KMOD_ZLIB_INFLATE">/dev/null 2>&1; then
		modprobe "$KMOD_ZLIB_INFLATE" >/dev/null 2>&1
	fi

	for KMOD in $KMOD_SPL $KMOD_SPLAT $KMOD_ZAVL $KMOD_ZNVPAIR \
	    $KMOD_ZUNICODE $KMOD_ZCOMMON $KMOD_ZLUA $KMOD_ICP $KMOD_ZFS; do
		load_module "$KMOD" || return 1
	done

	if [ "$VERBOSE" = "yes" ]; then
		echo "Successfully loaded ZFS module stack"
	fi

	return 0
}

unload_module() {
	KMOD=$1

	NAME=$(basename "$KMOD" .ko)
	FILE=$(modinfo "$KMOD" | awk '/^filename:/ {print $2}')
	VERSION=$(modinfo "$KMOD" | awk '/^version:/ {print $2}')

	if [ "$VERBOSE" = "yes" ]; then
		echo "Unloading: $KMOD ($VERSION)"
	fi

	rmmod "$NAME" || echo "Failed to unload $NAME"

	return 0
}

unload_modules() {
	for KMOD in $KMOD_ZFS $KMOD_ICP $KMOD_ZLUA $KMOD_ZCOMMON $KMOD_ZUNICODE \
	    $KMOD_ZNVPAIR  $KMOD_ZAVL $KMOD_SPLAT $KMOD_SPL; do
		NAME=$(basename "$KMOD" .ko)
		USE_COUNT=$(lsmod | grep -E "^${NAME} " | awk '{print $3}')

		if [ "$USE_COUNT" = "0" ] ; then
			unload_module "$KMOD" || return 1
		fi
	done

	if modinfo "$KMOD_ZLIB_DEFLATE" >/dev/null 2>&1; then
		modprobe -r "$KMOD_ZLIB_DEFLATE" >/dev/null 2>&1
	fi

	if modinfo "$KMOD_ZLIB_INFLATE">/dev/null 2>&1; then
		modprobe -r "$KMOD_ZLIB_INFLATE" >/dev/null 2>&1
	fi

	if [ "$VERBOSE" = "yes" ]; then
		echo "Successfully unloaded ZFS module stack"
	fi

	return 0
}

stack_clear() {
	STACK_MAX_SIZE=/sys/kernel/debug/tracing/stack_max_size
	STACK_TRACER_ENABLED=/proc/sys/kernel/stack_tracer_enabled

	if [ -e "$STACK_MAX_SIZE" ]; then
		echo 1 >"$STACK_TRACER_ENABLED"
		echo 0 >"$STACK_MAX_SIZE"
	fi
}

stack_check() {
	STACK_MAX_SIZE=/sys/kernel/debug/tracing/stack_max_size
	STACK_TRACE=/sys/kernel/debug/tracing/stack_trace
	STACK_LIMIT=7600

	if [ -e "$STACK_MAX_SIZE" ]; then
		STACK_SIZE=$(cat "$STACK_MAX_SIZE")

		if [ "$STACK_SIZE" -ge "$STACK_LIMIT" ]; then
			echo
			echo "Warning: max stack size $STACK_SIZE bytes"
			cat "$STACK_TRACE"
		fi
	fi
}

if [ "$(id -u)" != 0 ]; then
	echo "Must run as root"
	exit 1
fi

if [ ${UNLOAD} ]; then
	kill_zed
	umount -t zfs -a
	stack_check
	unload_modules
else
	stack_clear
	check_modules || die "${ERROR}"
	load_modules "$@" || die "Failed to load modules"
	wait_udev /dev/zfs 30 || die "'/dev/zfs' was not created"
fi

exit 0
