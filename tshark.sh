#!/bin/sh
# Executing tshark as a non-root user requires you to belonging group 'wireshark'
# and you need to run:
# sudo chown root:wireshark local/bin/dumpcap
# sudo setcap cap_net_raw,cap_net_admin=eip local/bin/dumpcap

exec ./local/bin/tshark -i lo -R libvirt -O libvirt -T pdml
