AM_CPPFLAGS = -I$(top_srcdir)/include

if !SYSTEMSTUN
lib_LTLIBRARIES = libstuncli.la

libstuncli_la_SOURCES = libstuncli.c
libstuncli_la_LDFLAGS = -no-undefined -avoid-version
endif

noinst_LTLIBRARIES = libnetchek_ops.la

libnetchek_ops_la_SOURCES = \
	utils.c 	    \
	config.c 	    \
	rules.c 	    \
	queue.c
libnetchek_ops_la_LIBADD = \
	$(MPTCPD_LIBS)     \
	-lmnl		   \
	-lnftnl 	   \
	-lnetfilter_queue
libnetchek_ops_la_LDFLAGS = -no-undefined -avoid-version
