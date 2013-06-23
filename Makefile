MAKEOPTS          = -j8

CC                = gcc
CFLAGS            = -Wall -g
LIBS              =

LOCAL_DIR         = local
LIBVIRT_DIR       = libvirt
WIRESHARK_DIR     = wireshark

GTAGS_FILES       = GTAGS GRTAGS GPATH

CONFIGURE_OPTS   += --prefix=$(abspath $(LOCAL_DIR))


.PHONY: libvirt wireshark gtags mprivozn-build

libvirt: $(LIBVIRT_DIR)/Makefile
	$(MAKE) $(MAKEOPTS) -C $(LIBVIRT_DIR) install

$(LIBVIRT_DIR)/Makefile: $(LIBVIRT_DIR)/configure
	cd $(LIBVIRT_DIR) && \
	./configure $(CONFIGURE_OPTS)

$(LIBVIRT_DIR)/configure: $(LIBVIRT_DIR)/bootstrap
	cd $(LIBVIRT_DIR) && ./bootstrap

wireshark: $(WIRESHARK_DIR)/Makefile
	$(MAKE) $(MAKEOPTS) -C $(WIRESHARK_DIR) install

$(WIRESHARK_DIR)/Makefile: $(WIRESHARK_DIR)/configure
	cd $(WIRESHARK_DIR) && \
	./configure $(CONFIGURE_OPTS)

$(WIRESHARK_DIR)/configure: $(WIRESHARK_DIR)/autogen.sh
	cd $(WIRESHARK_DIR) && ./autogen.sh

gtags: $(GTAGS_FILES)

$(GTAGS_FILES): $(shell find . -name '*.[ch]')
	gtags -v

# Build wireshark with dissector provided by mprivozn
mprivozn-build:
	cd $(WIRESHARK_DIR) && \
	patch -p1 --no-backup-if-mismatch < ../patch/dissector-mprivozn.patch

	touch $(WIRESHARK_DIR)/configure
	CONFIGURE_OPTS="--program-suffix=-mprivozn" \
	  $(MAKE) wireshark

	cd $(WIRESHARK_DIR) && \
	patch -p1 --no-backup-if-mismatch -R < ../patch/dissector-mprivozn.patch


SRCDIR       = src
SRCS         = $(patsubst %, $(SRCDIR)/%, packet-libvirt.c)
HEADERS      = $(patsubst %, $(SRCDIR)/%, packet-libvirt.h libvirt-const.h libvirt-remote-def.h libvirt-qemu-def.h libvirt-lxc-def.h)

INCLUDES     = $(LOCAL_DIR)/include ./wireshark ./wireshark/epan/dissectors /usr/include/glib-2.0 /usr/lib/glib-2.0/include

$(SRCDIR)/packet-libvirt.o: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -fPIC -c $(patsubst %, -I%, $(INCLUDES)) $< -o $@

$(SRCDIR)/plugin.c: $(SRCS)
	./util/make-dissector-reg.py $(SRCDIR) plugin $(SRCDIR)/packet-libvirt.c
	mv plugin.c $@

$(SRCDIR)/plugin.o: $(SRCDIR)/plugin.c
	$(CC) $(CFLAGS) -fPIC -c $(patsubst %, -I%, $(INCLUDES)) $< -o $@

$(SRCDIR)/libvirt.so: $(SRCDIR)/packet-libvirt.o $(SRCDIR)/plugin.o
	$(CC) -fPIC -shared -Wl,-soname=libvirt.so -o $@ $(SRCDIR)/plugin.o $(SRCDIR)/packet-libvirt.o -lwireshark
