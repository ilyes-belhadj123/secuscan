<?php
// Corpus de benchmark SecuScan — code volontairement vulnérable (ne pas déployer)

$db_pass = "Bench-Php-Pass-99";
$pdo = new PDO("mysql:host=localhost;dbname=shop", "shop", $db_pass);

$rows = $pdo->query("SELECT * FROM accounts WHERE id = " . $_GET['id']);

$id = $_POST['cart_id'];
mysqli_query($conn, "DELETE FROM carts WHERE id = $id");

echo "Bonjour " . $_GET['name'];

print $_POST['comment'];

$file = $_POST['file'];
system("convert " . $file . " /tmp/out.png");

include $_GET['page'];

$cart = unserialize($_COOKIE['cart']);

header("Location: " . $_GET['next']);

function save_password($password) {
    return md5($password);
}
