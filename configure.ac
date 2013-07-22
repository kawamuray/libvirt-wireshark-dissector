dnl Process this file with autoconf to produce a configure script.

dnl Copyright (C) 2013 Yuto Kawamura(kawamuray) <kawamuray.dadada@gmail.com>
dnl
dnl Author: Yuto Kawamura(kawamuray)
dnl
dnl This program is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU General Public License
dnl as published by the Free Software Foundation; either version 3
dnl of the License, or (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program. If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.69])
AC_INIT([libvirt-wireshark-dissector], [0.0.1], [kawamuray.dadada@gmail.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([ -Wall -Werror -Wno-portability foreign ])
AC_CONFIG_SRCDIR([src/packet-libvirt.c])
AM_CONFIG_HEADER([src/config.h])

# Utility scripts directory
AC_SUBST([UTILDIR], [$(cd `dirname $0`; pwd)/util])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_PATH_PROG([PYTHON], [python])
if test -z "$PYTHON"; then
    AC_MSG_ERROR([Cannot find python executable])
fi

# Arguments handling
AC_ARG_ENABLE([genproto], [AC_HELP_STRING([--enable-genproto=/path/to/libvirt/dist],
                           [enable generation of protocol definition from specified libvirt distribution])],
[
    AC_PATH_PROG([PERL], [perl])
    if test -z "$PERL"; then
        AC_MSG_ERROR([Cannot find perl executable])
    fi
    AC_SUBST([LIBVIRT_DISTDIR], [`echo "$enableval" | perl -MFile::Spec -pne 'File::Spec->rel2abs($_)'`])
])
AM_CONDITIONAL([ENABLE_GENPROTO], test -n "$enable_genproto")

AC_ARG_WITH([protofiles], [AC_HELP_STRING([--with-protofiles="remote/remote_protocol.x rpc/virkeepaliveprotocol.x"],
                                          [specify libvirt protocol definition files that will used to generate dissector.(default: remote/(remote|qemu|lxc)_protocol.x, rpc/virkeepaliveprotocol.x)])],
[
    if test -z "$enable_genproto"; then
        AC_MSG_WARN([Specifying --with-protofiles without specifying --enable-genproto feature has no effect])
    fi
    PROTOFILES="$withval"
], [
    PROTOFILES="remote/remote_protocol.x remote/qemu_protocol.x remote/lxc_protocol.x rpc/virkeepaliveprotocol.x"
])
AC_SUBST([PROTOFILES])

# Determine Wiresharks plugins directory from option or libwireshark location
AC_ARG_WITH([plugindir], [AC_HELP_STRING([--with-plugindir],
	                  [specify Wireshark plugins directory you want to install this dissector])],
[ plugindir=$withval ],
[
    AC_PATH_PROG([WIRESHARK], [wireshark])
    AC_PATH_PROG([WIRESHARK], [tshark])
    if test -z "$WIRESHARK"; then
        AC_MSG_ERROR([Cannot find executable wireshark or tshark])
    fi
    wireshark_version=`$WIRESHARK -v | grep -iE 'wireshark|tshark' | head -1 | cut -f 2 -d' '`
    AC_CHECK_LIB([wireshark], [proto_register_field_array], [
        plugindir=`dirname $WIRESHARK`/../lib/wireshark/plugins/$wireshark_version
    ], [AC_MSG_ERROR([Cannot find a Wireshark library])])
])
AC_SUBST([plugindir])

# Checks for libraries.
PKG_CHECK_MODULES([GLIB], [glib-2.0])

# Checks for header files.
CPPFLAGS_save="$CPPFLAGS"
# TODO: consider more better way
CPPFLAGS="$CPPFLAGS `pkg-config --cflags glib-2.0` -I`dirname $WIRESHARK`/../include/wireshark"
AC_CHECK_HEADERS([rpc/types.h])
AC_CHECK_HEADERS([rpc/xdr.h], [], [AC_MSG_ERROR([Cannot find header file rpc/xdr.h])],
                [#ifdef HAVE_RPC_TYPES_H
		 #include <rpc/types.h>
		 #endif])
AC_CHECK_HEADERS([glib.h], [], [AC_MSG_ERROR([Cannot find header file glib.h])])
AC_CHECK_HEADERS([wireshark/config.h], [], [AC_MSG_ERROR([Cannot find header file wireshark/config.h])])
AC_CHECK_HEADERS([wireshark/epan/packet.h wireshark/epan/dissectors/packet-tcp.h], [],
                 [AC_MSG_ERROR([Cannot find header file wireshark/epan/packet.h and wireshark/epan/dissectors/packet-tcp.h])],
		 [#include <wireshark/config.h>])
AC_SUBST([AM_CPPFLAGS], ["$CPPFLAGS -I. -Wall"])
CPPFLAGS="$CPPFLAGS_save"

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
