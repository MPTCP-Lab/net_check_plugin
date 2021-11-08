## SPDX-License-Identifier: BSD-3-Clause
##
## Copyright (c) 2017-2019, Intel Corporation

#MPTCPD_CFLAGS = \
#	-I/usr/local/include/mptcpd/ -I/usr/include/ell/
#MPTCPD_LIBS = -L/usr/local/lib/mptcpd -lmptcpd #-lmnl
#MPTCPD_PLUGINDIR = /usr/local/lib/mptcpd

plugindir = @MPTCPD_PLUGINDIR@
lib_LTLIBRARIES = net_check.la

net_check_la_SOURCES  = net_check.c
net_check_la_CFLAGS   = $(MPTCPD_CFLAGS)
net_check_la_LDFLAGS  = -no-undefined -module -avoid-version	
net_check_la_LIBADD   = $(MPTCPD_LIBS)
