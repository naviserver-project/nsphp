#
# nsphp configuration test.
#


set homedir [pwd]/tests
set bindir  [file dirname [ns_info nsd]]

ns_section "ns/parameters"
ns_param   home           $homedir
ns_param   tcllibrary     $bindir/../tcl
ns_param   logdebug       false

ns_section "ns/servers"
ns_param   test            "Test Server"

ns_section "ns/server/test/tcl"
ns_param   initfile        ${bindir}/init.tcl
ns_param   library         $homedir/modules

ns_section "ns/server/test/modules"
ns_param   nsdb            $bindir/nsdb.so
ns_param   nssock          $bindir/nssock.so
ns_param   nsphp           $homedir/../libphp5.so

ns_section "ns/server/test/module/nssock"
ns_param   port            8080
ns_param   hostname        localhost
ns_param   address         127.0.0.1

ns_section "ns/server/test/module/nsphp"
ns_param   map             *.php
ns_param   map             *.php4

