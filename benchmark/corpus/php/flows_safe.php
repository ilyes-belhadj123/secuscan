<?php
// Benchmark : mêmes fonctionnalités que flows.php, écrites de façon sûre (aucune alerte attendue).
$pdo = new PDO(getenv('DB_DSN'), getenv('DB_USER'), getenv('DB_PASSWORD'));

$name = $_GET['name'] ?? '';
echo "<p>Bonjour " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</p>";

$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
$stmt->execute([$id]);

$feed = $_POST['feed'];
$content = file_get_contents("https://feeds.example.com/" . rawurlencode($feed));

$host = $_GET['host'];
$output = shell_exec("ping -c 1 " . escapeshellarg($host));

$next = $_GET['next'];
header("Location: /compte");
