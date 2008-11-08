<?php
$test = @$_COOKIE["test"];

if ($test == "1") {
   header("HTTP/1.0 304 Not Modified");
   exit();
}
setcookie("test", "1", time() + 60, '/');

?>
test page
