#!/bin/sh

export LIBVIRT_DEBUG=debug
exec ./local/sbin/libvirtd --config=./local/etc/libvirt/libvirtd.conf --listen
