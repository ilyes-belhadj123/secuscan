<?php
// Benchmark : flux de données sur plusieurs lignes (vulnérable).
$pdo = new PDO(getenv('DB_DSN'), getenv('DB_USER'), getenv('DB_PASSWORD'));

$name = $_GET['name'] ?? '';
echo "<p>Bonjour " . $name . "</p>";

$id = $_GET['id'];
$sql = "SELECT * FROM orders WHERE id = $id";
$rows = $pdo->query($sql);

$feed = $_POST['feed'];
$content = file_get_contents($feed);

$host = $_GET['host'];
$output = shell_exec("ping -c 1 " . $host);

$next = $_GET['next'];
header("Location: " . $next);
