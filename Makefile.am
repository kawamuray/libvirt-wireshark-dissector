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
LIBVIRTDIR        = libvirt

# WIRESHARK_VERSION := $(shell wireshark --version | head -1 | cut -f 2 -d ' ')
INSTALLDIR        = $(HOME)/.wireshark/plugins

UTILDIR           = util

SRCDIR            = src
LIBVIRT_SO        = $(SRCDIR)/libvirt.so

all: $(LIBVIRT_SO)

.PHONY: $(LIBVIRT_SO)
$(LIBVIRT_SO):
	LIBVIRTDIR=$(abspath $(LIBVIRTDIR)) \
	UTILDIR=$(abspath $(UTILDIR)) \
	  $(MAKE) -C $(SRCDIR) all

install: all
	mkdir -p $(INSTALLDIR)
	cp $(LIBVIRT_SO) $(INSTALLDIR)

clean:
	$(MAKE) -C $(SRCDIR) clean
