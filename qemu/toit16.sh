#!/bin/bash

# vm config
mem=512
dsk="$HOME/pandavm/debian-toit16.qcow2"
os=linux-32-debian-3.2.81-486
redir="-redir tcp:10080::80 -redir tcp:10022::22"
mode="replay"
#rpl=test16
rpl=vtrip

if [ "$1" != "" ]; then
	mode="$1"
	shift
fi
if [ "$1" != "" ]; then
	rpl="$1"
	shift
fi

# qemu paths
qemu_target=i386
panda_path=/home/mstamat/panda
qemu_path="$panda_path"/qemu/"$qemu_target"-softmmu
qemu="$qemu_path"/qemu-system-"$qemu_target"

# environment
export LD_LIBRARY_PATH="$qemu_path"/panda_plugins
if [ "$mode" = "record" ]; then
	export DISPLAY=":99"
fi

echo "QEMU: $qemu"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "DISPLAY: $DISPLAY"
echo "VM: $(basename "$dsk") ${mem}MB $os"

if [ "$mode" = "record" ]; then
	echo ""
	echo $qemu -m "$mem" -hda "$dsk" -monitor stdio $redir

elif [ "$mode" = "replay" ]; then
	echo "REPLAY: $rpl"
	echo ""
	$qemu -m "$mem" -hda "$dsk" -display none -replay "$rpl" -os "$os" $*

elif [ "$mode" = "test" ]; then
	echo "REPLAY: $rpl"
	echo ""
	$qemu -m "$mem" -hda "$dsk" -display none -replay "$rpl" -os "$os" \
		-panda osi \
		-panda syscalls2:profile=linux_x86 \
		-panda file_taint:filename=index.html \
		-panda file_taint_sink:sink=index.html \
		#-panda file_taint:filename=hello.txt \
		#-panda file_taint_sink:sink=hellov.txt+lol.txt \
		#-pandalog hello.plog
else
	echo "Invalid mode."
	exit 1
fi

#-panda tainted_branch \
#-replay test16 -os linux-32-debian-3.2.81-486 -panda 'osi;osi_linux;prov_tracer'
#-panda osi_linux:kconf_group=debian-3.2.63-i686 \
