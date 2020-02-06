#
# nsphp configuration test.
#
ns_section "test"
ns_param   home   [pwd]/tests

foreach loopback [expr {[ns_info ipv6] ? [list ::1 "127.0.0.1"] : "127.0.0.1"}] {
    for {set port 8000} {$port < 8100} {incr port} {
        if {![catch {
            ns_log notice "try $loopback $port"
            close [ns_socklisten $loopback $port]
        } msg]} {
            set ok 1
            break
        }
    }
    if {[info exists ok]} {
        break
    }
}

ns_param   listenport       [expr {$port < 8100 ? $port : 0}]
ns_param   loopback         $loopback

if {[string match *:* $loopback]} {
    ns_param   listenurl    http://\[$loopback\]:[ns_config test listenport]
} else {
    ns_param   listenurl    http://$loopback:[ns_config test listenport]
}

ns_log notice "configure LOOPBACK  $loopback"
ns_log notice "configure LISTENURL [ns_config test listenurl]"

set homedir [pwd]/tests
set bindir  [file dirname [ns_info nsd]]

ns_section "ns/parameters"
ns_param   home           $homedir
ns_param   tcllibrary     $bindir/../tcl
ns_param   logdebug       false

ns_section "ns/servers"
ns_param   test            "Test Server"

ns_section "ns/modules" {
    if {[ns_config "test" listenport]} {
	#ns_param   nssock [ns_config "test" home]/../nssock/nssock
        ns_param   nssock          $bindir/nssock.so
    }
}

ns_section "ns/server/test/tcl"
ns_param   initfile        ${bindir}/init.tcl
ns_param   library         $homedir/modules

ns_section "ns/server/test/modules"
ns_param   nsdb            $bindir/nsdb.so
ns_param   nsphp           $homedir/../nsphp.so

ns_section "ns/module/nssock"
ns_param   port            [ns_config "test" listenport]
ns_param   hostname        localhost
ns_param   address         [ns_config "test" loopback]
ns_param   defaultserver   test


ns_section "ns/server/test/module/nsphp"
ns_param   map             *.php
#ns_param   map             *.php4

