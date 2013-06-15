MAKE              = make
MAKEOPTS          = -j8

CC                = gcc
CFLAGS            = -Wall -g
LIBS              = -lvirt

LOCAL_DIR         = local
LIBVIRT_DIR       = libvirt
WIRESHARK_DIR     = wireshark

GTAGS_FILES       = GTAGS GRTAGS GPATH


.PHONY: libvirt wireshark

libvirt: $(LIBVIRT_DIR)/Makefile
	$(MAKE) $(MAKEOPTS) -C $(LIBVIRT_DIR) install

$(LIBVIRT_DIR)/Makefile: $(LIBVIRT_DIR)/configure
	cd $(LIBVIRT_DIR) && \
	./configure --prefix=$(abspath $(LOCAL_DIR))

wireshark: $(WIRESHARK_DIR)/Makefile
	$(MAKE) $(MAKEOPTS) -C $(WIRESHARK_DIR) install

$(WIRESHARK_DIR)/Makefile: $(WIRESHARK_DIR)/configure
	cd $(WIRESHARK_DIR) && \
	./configure --prefix=$(abspath $(LOCAL_DIR))

$(GTAGS_FILES): $(shell find . -name '*.[ch]')
	gtags -v
