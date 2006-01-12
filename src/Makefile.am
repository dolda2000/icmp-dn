bin_PROGRAMS		= idnlookup
sbin_PROGRAMS		= icmpdnd
man_MANS		= idnlookup.1 icmpdnd.8 nss-icmp.7 nss-icmp.conf.5

lib_LTLIBRARIES		= libnss_icmp.la
libnss_icmp_la_SOURCES	= nss-icmp.c
libnss_icmp_la_CFLAGS	= -DCONFIGFILE="\"$(sysconfdir)/nss-icmp.conf\""
libnss_icmp_la_LDFLAGS	= -module -version-info '2'
