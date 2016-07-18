#!/bin/bash

mem=512
dsk="$HOME/pandavm/debian-toit16.qcow2"
#rpl=test16
rpl=vtrip
os=linux-32-debian-3.2.81-486

qemu_target=i386
panda_path=/home/mstamat/panda
qemu_path="$panda_path"/qemu/"$qemu_target"-softmmu
qemu="$qemu_path"/qemu-system-"$qemu_target"

export LD_LIBRARY_PATH="$qemu_path"/panda_plugins
echo "QEMU: $qemu"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "VM: $(basename "$dsk") ${mem}MB $os"
echo "REPLAY: $rpl"
echo ""

$qemu -m "$mem" -hda "$dsk" -replay "$rpl" -os "$os" -panda osi \
	-panda syscalls2:profile=linux_x86 \
	-panda file_taint:filename=hello.txt \
	-panda file_taint_sink
	#-pandalog hello.plog

#-panda tainted_branch \
#-replay test16 -os linux-32-debian-3.2.81-486 -panda 'osi;osi_linux;prov_tracer'
#-panda osi_linux:kconf_group=debian-3.2.63-i686 \
