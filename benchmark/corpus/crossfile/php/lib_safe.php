<?php
// Benchmark : fonctions appelées uniquement avec des entiers depuis index_safe.php (aucune alerte attendue).

function show_document($id) {
    readfile('/srv/documents/' . $id . '.pdf');
}

function load_partner_logo($partnerId) {
    return file_get_contents('https://partners.example.com/logos/' . $partnerId . '.png');
}
