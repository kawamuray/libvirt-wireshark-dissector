#!/bin/sh
set -e
set -x

cd libvirt
./bootstrap

cd ../wireshark
./autogen.sh
