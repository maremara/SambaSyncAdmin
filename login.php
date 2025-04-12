<?php
/**
 * LOGIN.PHP - Sistema de autenticação seguro
 */
session_start();
require_once 'config.php';
require_once 'functions.php';

// Ensure all required functions are defined
if (!function_exists('forceHTTPS') || !function_exists('setSecurityHeaders') || 
    !function_exists('isLoggedIn') || !function_exists('sanitizeInput') || 
    !function_exists('connectDB') || !function_exists('verifyPassword') || 
    !function_exists('regenerateSession') || !function_exists('logActivity') || 
    !function_exists('generateCSRFToken') || !function_exists('verifyCSRFToken')) {
    die('Erro: Funções necessárias não estão definidas.');
}

// Forçar uso de HTTPS
forceHTTPS();

// Definir cabeçalhos de segurança
setSecurityHeaders();

// Verificar se o usuário já está logado
if (isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$error = '';

// Processar o formulário de login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificar token CSRF
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Erro de segurança: token inválido. Tente novamente.';
    } else {
        // Sanitizar entrada
        $username = sanitizeInput($_POST['username'] ?? '');
        $password = $_POST['password'] ?? ''; // Não sanitizar a senha para não alterar caracteres especiais
        
        if (empty($username) || empty($password)) {
            $error = 'Por favor, preencha todos os campos.';
        } else {
            // Verificar as credenciais no banco de dados
            $db = connectDB();
            $stmt = $db->prepare("SELECT id, username, password FROM admins WHERE username = :username");
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && verifyPassword($password, $user['password'])) {
                // Login bem-sucedido - regenerar ID de sessão para prevenir fixação de sessão
                regenerateSession();
                
                // Armazenar dados do usuário na sessão
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['is_admin'] = true;
                $_SESSION['last_activity'] = time();
                
                // Atualizar data do último login
                $updateStmt = $db->prepare("UPDATE admins SET last_login = NOW() WHERE id = :id");
                $updateStmt->bindParam(':id', $user['id']);
                $updateStmt->execute();
                
                // Registrar atividade
                logActivity($user['id'], 'login', 'Login bem-sucedido');
                
                // Redirecionar para a página inicial
                header('Location: index.php');
                exit;
            } else {
                // Atraso para dificultar ataques de força bruta
                sleep(1);
                $error = 'Nome de usuário ou senha incorretos.';
                
                // Registrar tentativa de login falha
                logActivity(null, 'failed_login', "Tentativa de login falha para o usuário: {$username}");
            }
        }
    }
}

// Gerar um novo token CSRF
$csrfToken = generateCSRFToken();

// Incluir o cabeçalho
include 'includes/header.php';
?>

<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card shadow">
                <div class="card-header bg-primary text-white">
                    <h4 class="text-center mb-0">Login do Administrador</h4>
                </div>
                <div class="card-body">
                    <?php if (!empty($error)): ?>
                        <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                    <?php endif; ?>
                    
                    <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                        <!-- Token CSRF oculto -->
                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                        
                        <div class="mb-3">
                            <label for="username" class="form-label">Nome de Usuário</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-user"></i></span>
                                <input type="text" class="form-control" id="username" name="username" required 
                                       value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="password" class="form-label">Senha</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-sign-in-alt"></i> Entrar
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<?php include 'includes/footer.php'; ?>