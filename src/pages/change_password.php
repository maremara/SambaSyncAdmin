<?php
/**
 * CHANGE_PASSWORD.PHP - Page to change user passwords securely
 */
session_start();
require_once 'config.php';
require_once 'functions.php';

// Check if user is logged in
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

$message = '';
$error = '';

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Invalid CSRF token. Please try again.';
    } else {
        // Sanitize inputs
        $username = sanitizeInput($_POST['username'] ?? '');
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        // Validate username format
        if (!validateUsername($username)) {
            $error = 'Invalid username format. Use only lowercase letters, numbers, and underscores (3-20 characters).';
        }
        // Validate new password strength
        elseif (!validatePassword($new_password)) {
            $error = 'New password must be at least 8 characters long and include uppercase, lowercase letters, and numbers.';
        }
        // Check new password confirmation
        elseif ($new_password !== $confirm_password) {
            $error = 'New password and confirmation do not match.';
        } else {
            // Verify current password from database
            try {
                $db = connectDB();
                $stmt = $db->prepare('SELECT password FROM samba_users WHERE username = :username');
                $stmt->bindParam(':username', $username);
                $stmt->execute();
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$user) {
                    $error = 'User not found.';
                } elseif (!verifyPassword($current_password, $user['password'])) {
                    $error = 'Current password is incorrect.';
                } else {
                    // Update password hash in database
                    $new_hash = hashPassword($new_password);
                    $updateStmt = $db->prepare('UPDATE samba_users SET password = :password WHERE username = :username');
                    $updateStmt->bindParam(':password', $new_hash);
                    $updateStmt->bindParam(':username', $username);
                    $updateStmt->execute();

                    $message = 'Password changed successfully.';
                    logActivity($_SESSION['user_id'], 'change_password', "Password changed for user $username");
                }
            } catch (PDOException $e) {
                $error = 'Database error: ' . htmlspecialchars($e->getMessage());
            }
        }
    }
}

// Generate CSRF token for the form
$csrf_token = generateCSRFToken();

?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Alterar Senha</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<?php include 'includes/header.php'; ?>

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

<?php include 'includes/footer.php'; ?>
</body>
</html>
