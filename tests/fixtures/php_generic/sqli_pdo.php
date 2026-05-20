<?php
$pdo = new PDO('mysql:host=localhost;dbname=test', 'u', 'p');
$id = $_GET['id'] ?? '';
$pdo->query("SELECT * FROM users WHERE id = " . $id);
