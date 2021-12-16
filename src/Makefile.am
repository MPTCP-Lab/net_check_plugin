AM_CPPFLAGS = 				\
	-I$(top_srcdir)/include		\
	-I$(top_builddir)/include

if SYSTEMSTUN
STUN_INC = -lstuncli
else
STUN_INC = $(top_builddir)/lib/libstuncli.la
endif


plugindir = @MPTCPD_PLUGINDIR@

plugin_LTLIBRARIES = net_check.la

net_check_la_SOURCES  = net_check.c
net_check_la_LIBADD   = 	              \
	$(top_builddir)/lib/libnetchek_ops.la \
	$(MPTCPD_LIBS)		  	      \
	-lnftnl			              \
	$(STUN_INC)

net_check_la_CFLAGS   = $(MPTCPD_CFLAGS)
net_check_la_LDFLAGS  = -no-undefined -module -avoid-version	
