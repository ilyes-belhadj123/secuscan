<?php
// Benchmark : mêmes appels entre fichiers, avec des valeurs converties en entiers (aucune alerte attendue).
require_once __DIR__ . '/lib_safe.php';

show_document(intval($_GET['id'] ?? 0));

$partner = intval($_POST['partner']);
load_partner_logo($partner);
