LIBVIRTDIR        = libvirt

WIRESHARK_VERSION := $(shell wireshark --version | head -1 | cut -f 2 -d ' ')
INSTALLDIR        = $(HOME)/.wireshark/plugins/$(WIRESHARK_VERSION)

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
