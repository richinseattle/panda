#!/bin/bash

# Get the location of the LLVM compiled for PANDA, respecting environment variables.
PANDA_LLVM_ROOT="${PANDA_LLVM_ROOT:-../llvm}"
PANDA_LLVM_BUILD="${PANDA_LLVM_BUILD:-Release}"
PANDA_LLVM="$(/bin/readlink -f "${PANDA_LLVM_ROOT}/${PANDA_LLVM_BUILD}" 2>/dev/null)"

# Stop on any error after this point.
set -e

# Set the LLVM_BIT.
if [ "$PANDA_LLVM" != "" ]; then
  # Using PANDA LLVM.
  echo "Found PANDA LLVM on ${PANDA_LLVM_ROOT} -- LLVM SUPPORT IS ENABLED"
  LLVM_BIT="--enable-llvm --with-llvm=${PANDA_LLVM}"
else
  # Fallback to system LLVM.
  if llvm-config --version >/dev/null 2>/dev/null && [ $(llvm-config --version) == "3.3" ]; then
    echo "Found SYSTEM LLVM -- LLVM SUPPORT IS ENABLED"
    LLVM_BIT="--enable-llvm --with-llvm=$(llvm-config --prefix)"
  elif llvm-config-3.3 --version >/dev/null 2>/dev/null; then
    echo "Found SYSTEM LLVM -- LLVM SUPPORT IS ENABLED"
    LLVM_BIT="--enable-llvm --with-llvm=$(llvm-config-3.3 --prefix)"
  else
    echo "No suitable LLVM found -- LLVM SUPPORT IS DISABLED"
    LLVM_BIT=""
  fi
fi  

# create api code for plugins
python ../scripts/apigen.py

# create pandalog code
make -C panda

# configure - if needed
if [ ! -f config-host.mak ]; then
  echo "No config-host.mak. Running configure script."
  ./configure --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu \
    --prefix=`pwd`/install \
    --disable-pie \
    --disable-xen \
    --disable-libiscsi \
    $LLVM_BIT \
    --extra-cflags="-O2 -I/usr/local/include -DOSI_PROC_EVENTS" \
    --extra-cxxflags="-O2" \
    --extra-ldflags="-L/usr/local/lib -L/usr/local/lib64 -lprotobuf-c -lprotobuf -lpthread"
else
  echo "Found config-host.mak. Not running configure script."
fi

# compile
make -j ${PANDA_NPROC:-$(nproc)}
