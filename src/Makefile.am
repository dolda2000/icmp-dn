bin_PROGRAMS		= idnlookup
sbin_PROGRAMS		= icmpdnd

lib_LTLIBRARIES		= libnss_icmp.la
libnss_icmp_la_SOURCES	= nss-icmp.c
libnss_icmp_la_CFLAGS	= -DCONFIGFILE="\"$(sysconfdir)/nss-icmp.conf\""
libnss_icmp_la_LDFLAGS	= -module -version-info '2'
