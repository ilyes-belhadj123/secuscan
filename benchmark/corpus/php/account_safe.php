<?php
// Corpus de benchmark SecuScan — code sûr (aucune alerte attendue)

$pdo = new PDO("mysql:host=localhost;dbname=shop", "shop", getenv("DB_PASSWORD"));

$stmt = $pdo->prepare("SELECT * FROM accounts WHERE id = ?");
$stmt->execute([$_GET['id']]);

echo "Bonjour " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

$host = $_POST['host'];
exec("ping -c 1 " . escapeshellarg($host), $output);

$allowed = ['home', 'contact', 'faq'];
$page = in_array($_GET['page'], $allowed, true) ? $_GET['page'] : 'home';
include __DIR__ . "/pages/" . $page . ".php";

$cart = json_decode($_COOKIE['cart'], true);

function save_password($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}
