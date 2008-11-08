<?php
$test = @$_COOKIE["test"];
setcookie("test", "1", time() + 60, '/');

if ($test == "1") {
   header("HTTP/1.0 304 Not Modified");
   exit();
}
?>
test page
