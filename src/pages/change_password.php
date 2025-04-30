<?php
require_once __DIR__ . '/../controllers/ChangePasswordController.php';

$controller = new ChangePasswordController();
$controller->handleRequest();

$csrf_token = generateCSRFToken();
$message = $controller->getMessage();
$error = $controller->getError();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Alterar Senha</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<?php include '../views/header.php'; ?>

<div class="container mt-5">
    <h2>Alterar Senha</h2>

    <?php if ($message): ?>
        <div class="alert alert-success" role="alert">
            <?= htmlspecialchars($message) ?>
        </div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="alert alert-danger" role="alert">
            <?= htmlspecialchars($error) ?>
        </div>
    <?php endif; ?>

    <form method="post" action="change_password.php" novalidate>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">

        <div class="mb-3">
            <label for="username" class="form-label">Nome de Usuário <span class="text-danger">*</span></label>
            <input type="text" class="form-control" id="username" name="username" required pattern="[a-z0-9_]{3,20}" title="Use apenas letras minúsculas, números e sublinhado (3-20 caracteres)" value="<?= isset($_POST['username']) ? htmlspecialchars($_POST['username']) : '' ?>">
            <div class="form-text">Use apenas letras minúsculas, números e sublinhado.</div>
        </div>

        <div class="mb-3">
            <label for="current_password" class="form-label">Senha Atual <span class="text-danger">*</span></label>
            <input type="password" class="form-control" id="current_password" name="current_password" required>
        </div>

        <div class="mb-3">
            <label for="new_password" class="form-label">Nova Senha <span class="text-danger">*</span></label>
            <input type="password" class="form-control" id="new_password" name="new_password" required>
            <div class="form-text">Pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula e um número.</div>
        </div>

        <div class="mb-3">
            <label for="confirm_password" class="form-label">Confirmar Nova Senha <span class="text-danger">*</span></label>
            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
        </div>

        <button type="submit" class="btn btn-primary">Alterar Senha</button>
    </form>
</div>

<?php include '../views/footer.php'; ?>
</body>
</html>
