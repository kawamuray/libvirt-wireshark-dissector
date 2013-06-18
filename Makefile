MAKEOPTS          = -j8

CC                = gcc
CFLAGS            = -Wall -g
LIBS              = -lvirt

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
