# Makefile
#
# Copyright (C) 2013 Yuto Kawamura(kawamuray) <kawamuray.dadada@gmail.com>
#
# Author: Yuto Kawamura(kawamuray)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
CC                = gcc
CFLAGS            = -Wall -O2 -g
LIBS              = -lwireshark
INCLUDES          = -I../local/include -I../wireshark -I../wireshark/epan/dissectors -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I.

XDRFILES          = $(patsubst %, $(LIBVIRTDIR)/src/%, remote/remote_protocol.x remote/qemu_protocol.x remote/lxc_protocol.x rpc/virkeepaliveprotocol.x)

objects           = packet-libvirt.o plugin.o
LIBVIRT_SO        = libvirt.so

all: $(LIBVIRT_SO)

$(LIBVIRT_SO): $(objects)
	$(CC) $(LIBS) $(CFLAGS) -fPIC -shared -Wl,-soname=libvirt.so -o $@ $(objects)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -c $< -o $@

packet-libvirt.c: packet-libvirt.h libvirt/protocol.h

plugin.c: packet-libvirt.c
	$(UTILDIR)/make-dissector-reg.py . plugin $<

libvirt/protocol.h: $(UTILDIR)/genxdrdef.pl $(XDRFILES)
	$(UTILDIR)/genxdrdef.pl $(XDRFILES)

clean:
	-rm -rf *.o *.so libvirt/*.h plugin.c
