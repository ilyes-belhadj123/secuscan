<?php
// Benchmark : entrée utilisateur transmise à des fonctions d'un autre fichier (vulnérable).
require_once __DIR__ . '/lib.php';

$file = $_GET['file'] ?? '';
show_attachment($file);

save_avatar($_POST['avatar']);
