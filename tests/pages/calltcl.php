<?php

echo " ns_info(name) ";     echo ns_info("name");
echo " ns_conn(server) ";   echo ns_conn("server");
echo " ns_conn(url) ";      echo ns_conn("url");
echo " ns_eval(conn url) "; echo ns_eval("ns_conn url");
echo " ns_queryexists(x) "; echo ns_queryexists("x");
echo " ns_queryget(x) ";    echo ns_queryget("x");

echo " ns_headers() ";      echo print_r(ns_headers());
echo " ns_header(content-type) "; echo ns_header("User-Agent");

?> 