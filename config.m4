dnl
dnl $Id$
dnl

RESULT=no
AC_MSG_CHECKING(for Naviserver support)

AC_ARG_WITH(naviserver,
[  --with-naviserver[=DIR]     Build PHP as Naviserver module],
[
if test "$withval" != "no"; then
        if test "$withval" = "yes"; then
                NS_PATH=/usr/local/ns # the default
        else
                NS_PATH=$withval
        fi
        test -f "$NS_PATH/include/ns.h" || AC_MSG_ERROR(Unable to find ns.h in $NS_PATH/include)
        PHP_BUILD_THREAD_SAFE
        AC_DEFINE(WITH_NAVISERVER,1,[whether you want Naviserver support])
        PHP_ADD_INCLUDE($NS_PATH/include)
        PHP_SELECT_SAPI(naviserver, shared, nsphp.c)
        INSTALL_IT="\$(SHELL) \$(srcdir)/install-sh -m 0755 $SAPI_SHARED \$(INSTALL_ROOT)$NS_PATH/bin/"
        RESULT=yes
else
        RESULT=no
fi
])
AC_MSG_RESULT($RESULT)


dnl ## Local Variables:
dnl ## tab-width: 4
dnl ## End:
