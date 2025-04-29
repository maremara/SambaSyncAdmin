<?php
/**
 * CREATE_USER.PHP - Página para criar novos usuários Samba com validação e segurança
 */
require_once 'config.php';
require_once 'functions.php';

// Forçar uso de HTTPS
forceHTTPS();

// Definir cabeçalhos de segurança
setSecurityHeaders();

// Verificar se o usuário está logado e é administrador
if (!isLoggedIn() || !isAdmin()) {
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
$formData = [
    'username' => '',
    'full_name' => '',
    'email' => ''
];

// Inicializar o gerenciador de usuários Samba
$sambaManager = new SambaUserManager($config);

// Processar o formulário de criação de usuário
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificar token CSRF
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        $error = 'Erro de segurança: token inválido. Tente novamente.';
    } else {
        // Sanitizar e validar entradas
        $username = sanitizeInput($_POST['username'] ?? '');
        $password = $_POST['password'] ?? ''; // Não sanitizar a senha para não alterar caracteres especiais
        $confirmPassword = $_POST['confirm_password'] ?? '';
        $fullName = sanitizeInput($_POST['full_name'] ?? '');
        $email = sanitizeInput($_POST['email'] ?? '');
        
        // Preservar dados do formulário para reexibição em caso de erro
        $formData = [
            'username' => $username,
            'full_name' => $fullName,
            'email' => $email
        ];
        
        // Validar nome de usuário
        if (empty($username)) {
            $error = 'Nome de usuário é obrigatório.';
        } elseif (!validateUsername($username)) {
            $error = 'Nome de usuário inválido. Use apenas letras minúsculas, números e underscore (3-20 caracteres).';
        }
        
        // Validar senha
        elseif (empty($password)) {
            $error = 'Senha é obrigatória.';
        } elseif (!validatePassword($password)) {
            $error = 'Senha inválida. Use pelo menos 8 caracteres, incluindo maiúsculas, minúsculas e números.';
        }
        
        // Confirmar senha
        elseif ($password !== $confirmPassword) {
            $error = 'As senhas não coincidem.';
        }
        
        // Validar e-mail se fornecido
        elseif (!empty($email) && !validateEmail($email)) {
            $error = 'E-mail inválido.';
        }
        
        // Se não houver erros, criar o usuário
        else {
            try {
                // Verificar se o usuário já existe no DB antes de tentar criar no Samba
                $db = connectDB();
                $checkStmt = $db->prepare("SELECT id FROM samba_users WHERE username = :username");
                $checkStmt->bindParam(':username', $username);
                $checkStmt->execute();
                
                if ($checkStmt->rowCount() > 0) {
                    $error = "Usuário '{$username}' já existe no banco de dados.";
                } else {
                    // Criar o usuário no Samba
                    $sambaManager->createUser($username, $password, $fullName, $email);
                    
                    // Registrar no banco de dados
                    $stmt = $db->prepare("
                        INSERT INTO samba_users (username, full_name, email)
                        VALUES (:username, :full_name, :email)
                    ");
                    $stmt->bindParam(':username', $username);
                    $stmt->bindParam(':full_name', $fullName);
                    $stmt->bindParam(':email', $email);
                    $stmt->execute();
                    
                    // Registrar atividade
                    logActivity($_SESSION['user_id'], 'create_user', "Usuário '{$username}' criado com sucesso.");
                    
                    $message = "Usuário '{$username}' criado com sucesso!";
                    
                    // Limpar os dados do formulário após criação bem-sucedida
                    $formData = [
                        'username' => '',
                        'full_name' => '',
                        'email' => ''
                    ];
                }
            } catch (Exception $e) {
                $error = 'Erro ao criar usuário: ' . $e->getMessage();
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
    <h1>Criar Novo Usuário Samba</h1>
    
    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="index.php">Início</a></li>
            <li class="breadcrumb-item active" aria-current="page">Criar Usuário</li>
        </ol>
    </nav>
    
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
            <h5 class="mb-0"><i class="fas fa-user-plus me-2"></i> Formulário de Criação de Usuário</h5>
        </div>
        <div class="card-body">
            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" class="needs-validation" novalidate>
                <!-- Token CSRF oculto -->
                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                
                <div class="row mb-3">
                    <div class="col-md-6">
                        <label for="username" class="form-label">Nome de Usuário <span class="text-danger">*</span></label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-user"></i></span>
                            <input type="text" class="form-control" id="username" name="username" 
                                   value="<?php echo htmlspecialchars($formData['username']); ?>" required pattern="[a-z0-9_]{3,20}">
                        </div>
                        <div class="form-text">Use apenas letras minúsculas, números e sublinhado (3-20 caracteres).</div>
                    </div>
                    
                    <div class="col-md-6">
                        <label for="full_name" class="form-label">Nome Completo</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-id-card"></i></span>
                            <input type="text" class="form-control" id="full_name" name="full_name" 
                                   value="<?php echo htmlspecialchars($formData['full_name']); ?>">
                        </div>
                    </div>
                </div>
                
                <div class="row mb-3">
                    <div class="col-md-6">
                        <label for="password" class="form-label">Senha <span class="text-danger">*</span></label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-lock"></i></span>
                            <input type="password" class="form-control" id="password" name="password" required minlength="8">
                            <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                        <div class="form-text">Use uma senha forte (mínimo 8 caracteres, incluindo maiúsculas, minúsculas e números).</div>
                    </div>
                    
                    <div class="col-md-6">
                        <label for="confirm_password" class="form-label">Confirmar Senha <span class="text-danger">*</span></label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-lock"></i></span>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required minlength="8">
                        </div>
                    </div>
                </div>
                
                <div class="mb-3">
                    <label for="email" class="form-label">E-mail</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="fas fa-envelope"></i></span>
                        <input type="email" class="form-control" id="email" name="email" 
                               value="<?php echo htmlspecialchars($formData['email']); ?>">
                    </div>
                </div>
                
                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                    <a href="index.php" class="btn btn-secondary">
                        <i class="fas fa-times me-2"></i> Cancelar
                    </a>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-user-plus me-2"></i> Criar Usuário
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Script para mostrar/ocultar senha -->
<script>
document.addEventListener('DOMContentLoaded', function() {
    const togglePassword = document.getElementById('togglePassword');
    const password = document.getElementById('password');
    
    togglePassword.addEventListener('click', function() {
        const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
        password.setAttribute('type', type);
        this.querySelector('i').classList.toggle('fa-eye');
        this.querySelector('i').classList.toggle('fa-eye-slash');
    });
});
</script>

<?php include 'includes/footer.php'; ?>