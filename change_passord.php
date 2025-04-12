<?php
/**
 * CHANGE_PASSWORD.PHP - Página para alterar senhas de usuários com segurança
 */
session_start();
require_once 'config.php';
require_once 'functions.php';

// Forçar uso de HTTPS
forceHTTPS();

// Definir cabeçalhos de segurança
setSecurityHeaders();

// Verificar se o usuário está logado
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// Verificar inatividade (30 minutos)
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
    session_unset();
    session_destroy();
    header('Location: login.php?expired=1');
    exit;
}
$_SESSION['last_activity'] = time();

$message = '';
$error = '';

// Se um usuário específico for solicitado (apenas administradores podem fazer isso)
$username = '';
if (isset($_GET['username']) && !empty($_GET['username']) && isAdmin()) {
    $username = sanitizeInput($_GET['username']);
} else {
    // Se não for especificado, usar o próprio usuário logado
    $username = $_SESSION['username'];
}

// Inicializar o gerenciador de usuários Samba
$sambaManager = new SambaUserManager($config);

// Verificar se o usuário existe
$userExists = false;
try {
    $userExists = $sambaManager->userExists($username);
} catch (Exception $e) {
    $error = 'Erro ao verificar usuário: ' . $e->getMessage();
}

// Processar o formulário de alteração de senha
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificar token CSRF
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Erro de segurança: token inválido. Tente novamente.';
    } else {
        // Se for um administrador alterando senha de outro usuário, não precisa da senha atual
        $isAdminChangingOtherUser = (isAdmin() && $username !== $_SESSION['username']);
        
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        // Validações
        if (!$isAdminChangingOtherUser && empty($currentPassword)) {
            $error = 'A senha atual é obrigatória.';
        } 
        elseif (empty($newPassword)) {
            $error = 'A nova senha é obrigatória.';
        } 
        elseif (!validatePassword($newPassword)) {
            $error = 'Senha inválida. Use pelo menos 8 caracteres, incluindo maiúsculas, minúsculas e números.';
        }
        elseif ($newPassword !== $confirmPassword) {
            $error = 'As senhas não coincidem.';
        }
        else {
            try {
                // Se não for um admin mudando senha de outro usuário, verificar a senha atual
                if (!$isAdminChangingOtherUser) {
                    // Para verificar a senha atual, é preciso consultar o banco de dados
                    $db = connectDB();
                    $stmt = $db->prepare("SELECT password FROM admins WHERE username = :username");
                    $stmt->bindParam(':username', $_SESSION['username']);
                    $stmt->execute();
                    $user = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$user || !verifyPassword($currentPassword, $user['password'])) {
                        $error = 'Senha atual incorreta.';
                    } else {
                        // Senha atual correta, prosseguir com a alteração
                        $sambaManager->changePassword($username, $newPassword);
                        
                        // Se for a própria senha do administrador, atualizar também no banco de dados
                        if ($username === $_SESSION['username']) {
                            $newHash = hashPassword($newPassword);
                            $updateStmt = $db->prepare("UPDATE admins SET password = :password WHERE username = :username");
                            $updateStmt->bindParam(':password', $newHash);
                            $updateStmt->bindParam(':username', $username);
                            $updateStmt->execute();
                        }
                        
                        // Registrar atividade
                        logActivity($_SESSION['user_id'], 'change_password', "Senha alterada para o usuário '{$username}'.");
                        
                        $message = "Senha alterada com sucesso.";
                    }
                }
            } catch (Exception $e) {
                $error = 'Erro ao alterar senha: ' . $e->getMessage();
            }
        }
    }
}

// Gerar um novo token CSRF
$csrfToken = generateCSRFToken();

// Incluir o cabeçalho
include 'includes/header.php';
?>

<div class="container mt-4">
    <h1>Alterar Senha</h1>
    
    <?php if (!empty($message)): ?>
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <i class="fas fa-check-circle me-2"></i> <?php echo htmlspecialchars($message); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Fechar"></button>
        </div>
    <?php endif; ?>
    
    <?php if (!empty($error)): ?>
        <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <i class="fas fa-exclamation-triangle me-2"></i> <?php echo htmlspecialchars($error); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Fechar"></button>
        </div>
    <?php endif; ?>
    
    <div class="card shadow">
        <div class="card-header bg-primary text-white">
            <h5 class="mb-0"><i class="fas fa-key me-2"></i> Alteração de Senha</h5>
        </div>
        <div class="card-body">
            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" class="needs-validation" novalidate>
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <?php if (isAdmin() && $username !== $_SESSION['username']): ?>
                    <div class="mb-3">
                        <label class="form-label">Alterando senha para: <strong><?php echo htmlspecialchars($username); ?></strong></label>
                    </div>
                <?php endif; ?>
                
                <?php if (!isAdmin() || $username === $_SESSION['username']): ?>
                    <div class="mb-3">
                        <label for="current_password" class="form-label">Senha Atual <span class="text-danger">*</span></label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-lock"></i></span>
                            <input type="password" class="form-control" id="current_password" name="current_password" required>
                        </div>
                    </div>
                <?php endif; ?>
                
                <div class="mb-3">
                    <label for="new_password" class="form-label">Nova Senha <span class="text-danger">*</span></label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                        <input type="password" class="form-control" id="new_password" name="new_password" required minlength="8">
                    </div>
                    <div class="form-text">Mínimo 8 caracteres, incluindo maiúsculas, minúsculas e números.</div>
                </div>
                
                <div class="mb-3">
                    <label for="confirm_password" class="form-label">Confirmar Nova Senha <span class="text-danger">*</span></label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-lock"></i></span>
                        <input type="password" class="form-control" id="confirm_password" name="confirm_password" required minlength="8">
                    </div>
                </div>
                
                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                    <a href="index.php" class="btn btn-secondary">
                        <i class="fas fa-times me-2"></i> Cancelar
                    </a>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save me-2"></i> Salvar
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<?php include 'includes/footer.php'; ?>
