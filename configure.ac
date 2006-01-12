#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([icmpdn], [0.4], [fredrik@dolda2000.com])
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_SRCDIR([src/nss-icmp.c])
AC_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([dup2 gethostname gettimeofday memset socket strchr])

AC_CONFIG_FILES([
Makefile
src/Makefile
admin/Makefile
admin/icmpdn.spec
src/idnlookup.1
src/nss-icmp.conf.5
src/nss-icmp.7
src/icmpdnd.8])
AC_OUTPUT
