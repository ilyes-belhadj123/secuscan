<?php
// Benchmark : fonctions appelées avec une entrée utilisateur depuis index.php (vulnérable).

function show_attachment($name) {
    readfile('/srv/attachments/' . $name);
}

function save_avatar($url) {
    $image = file_get_contents($url);
    file_put_contents('/srv/avatars/current.png', $image);
}
