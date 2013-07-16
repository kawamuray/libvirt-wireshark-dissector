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
