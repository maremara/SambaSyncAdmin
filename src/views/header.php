<?php
// Garante que a variável $title sempre tenha um valor
if (!isset($title)) {
    $title = "Painel de Gerenciamento Samba";
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title) ?></title>

    <!-- Favicon -->
    <link rel="icon" href="/favicon.ico" type="image/x-icon">

    <!-- Estilos -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- Seus estilos personalizados -->
    <link rel="stylesheet" href="/assets/css/style.css">

    <!-- Meta tags extras (SEO / segurança) -->
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
        <div class="container-fluid">
            <a class="navbar-brand" href="/index.php">Samba Admin</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="/usuarios.php">Usuários</a></li>
                    <li class="nav-item"><a class="nav-link" href="/importar.php">Importar</a></li>
                    <li class="nav-item"><a class="nav-link" href="/logs.php">Logs</a></li>
                    <li class="nav-item"><a class="nav-link" href="/logout.php">Sair</a></li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container">
