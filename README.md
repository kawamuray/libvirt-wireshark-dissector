\*\*CAUTION\*\*
===============
<span style="color: red;font-size: 30px;">**This project was merged into libvirt project. This repository will not maintained anymore. Please refer to [libvirt.git](http://libvirt.org/git/?p=libvirt.git) repository for newest releases.**</span>

About
=====
This is the project of Google Summer of Code 2013 accepted by QEMU.org and libvirt community.
The goal of this project is, provide Wireshark dissector for Libvirt RPC protocol. It will provide Libvirt packet overview/detail analysing in Wireshark. Furthermore, it will be able to build(generated) from RPC protocol definition placed in Libvirt source tree to support latest protocol specification.

See also:
- http://www.google-melange.com/gsoc/project/google/gsoc2013/kawamuray/7001
- http://wiki.qemu.org/Features/LibvirtWiresharkDissector

Installation
=============
Generate ./configure script
---------------------------
Run following commands on top directory of libvirt-wireshark-dissector:

    autoreconf --install

Basic installation
------------------
Basic installation uses distributed XDR dissector definition files(src/libvirt.dist/*.h) to build dissector.
Run following commands on top directory of libvirt-wireshark-dissector:

    ./configure && make
    sudo make install

Installation with generating XDR dissector from your libvirt source tree
------------------------------------------------------------------------
This build generates XDR dissector definition files(src/libvirt.gen/*.h) from your libvirt source tree.
You should specify --enable-genproto=</path/to/your/libvirt/source/tree> switch to ./configure.
You can add --with-protofiles=<protoA.x protoB.x ...> option to specify which protocol should be supported by dissector. Paths should be relative from dir you specified on --enable-genproto. Default value of this option is "remote/remote\_protocol.x remote/qemu\_protocol.x remote/lxc\_protocol.x rpc/virkeepaliveprotocol.x".
Following is a example of build using dissector generation feature:

    ./configure --enable-genproto=$HOME/libvirt && make
    sudo make install

Changing installation directory
-------------------------------
You can change installation directory of pluggable shared object(libvirt.so) by specifying --with-plugindir=<path>.

You can install libvirt.so into your local wireshark plugin directory:

    ./configure --with-plugindir=$HOME/.wireshark/plugins
