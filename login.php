<?php
/**
 * LOGIN.PHP - Sistema de autenticação seguro
 */
require_once 'config.php';
require_once 'functions.php';

// Verificações essenciais
if (!function_exists('forceHTTPS') || !function_exists('setSecurityHeaders') || 
    !function_exists('isLoggedIn') || !function_exists('sanitizeInput') || 
    !function_exists('connectDB') || !function_exists('verifyPassword') || 
    !function_exists('regenerateSession') || !function_exists('logActivity') || 
    !function_exists('generateCSRFToken') || !function_exists('verifyCSRFToken')) {
    die('Erro: Funções necessárias não estão definidas.');
}

// Forçar HTTPS e aplicar headers de segurança
forceHTTPS();
setSecurityHeaders();

// Redirecionar se já estiver logado
if (isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$error = '';

// Processa o login se for POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Erro de segurança: token inválido.';
    } else {
        $username = sanitizeInput($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username && $password) {
            $db = connectDB();
            $stmt = $db->prepare('SELECT * FROM users WHERE username = ?');
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && verifyPassword($password, $user['password'])) {
                regenerateSession();
                $_SESSION['user'] = $user['username'];
                $_SESSION['is_admin'] = $user['is_admin'];
                logActivity("Login bem-sucedido para usuário: $username");
                header('Location: index.php');
                exit;
            } else {
                $error = 'Usuário ou senha inválidos.';
                logActivity("Falha no login para usuário: $username");
            }
        } else {
            $error = 'Preencha todos os campos.';
        }
    }
}

// Gerar token CSRF
$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Login - Gerenciador Samba</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css">
</head>
<body>
<div class="container mt-5">
    <h2>Login</h2>

    <?php if (!empty($error)): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
    <?php endif; ?>

    <form method="POST" action="">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
        <div class="mb-3">
            <label for="username" class="form-label">Usuário</label>
            <input type="text" class="form-control" name="username" id="username" required>
        </div>
        <div class="mb-3">
            <label for="password" class="form-label">Senha</label>
            <input type="password" class="form-control" name="password" id="password" required>
        </div>
        <button type="submit" class="btn btn-primary">Entrar</button>
    </form>
</div>
</body>
</html>
