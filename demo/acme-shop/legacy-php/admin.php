<?php
// Acme Shop — ancien back-office (démonstration volontairement vulnérable)

$db_password = "Legacy-Admin-2026!";
$conn = mysqli_connect("localhost", "acme_admin", $db_password, "acme");

// Recherche de client
$email = $_GET['email'];
$result = mysqli_query($conn, "SELECT * FROM customers WHERE email = '" . $email . "'");

while ($row = mysqli_fetch_assoc($result)) {
    echo "<tr><td>" . $row['name'] . "</td></tr>";
}

// Message de confirmation
echo "<p>Résultats pour : " . $_GET['email'] . "</p>";

// Chargement dynamique de module
$module = $_GET['module'];
include($module . ".php");

// Préférences stockées dans un cookie
$prefs = unserialize($_COOKIE['prefs']);

// Outil de diagnostic
$host = $_POST['host'];
$output = shell_exec("nslookup " . $host);
echo "<pre>$output</pre>";

function check_password($input, $stored_hash) {
    return md5($input) == $stored_hash;
}
