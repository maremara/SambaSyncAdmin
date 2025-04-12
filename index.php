<?php
/**
 * INDEX.PHP - Pagina inicial do sistema
 */
session_start();
require_once 'config.php';
require_once 'functions.php';

// Verificar se o usuario esta logado
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

// Inicializar o gerenciador de usuarios Samba
$sambaManager = new SambaUserManager($config);

// Obter a lista de usuarios se for um administrador
$users = [];
if (isAdmin()) {
    try {
        $users = $sambaManager->listUsers();
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Incluir o cabecalho
include 'includes/header.php';
?>

<div class="container mt-4">
    <h1>Sistema de Gerenciamento de Senhas Samba</h1>
    
    <?php if (isset($error)): ?>
        <div class="alert alert-danger"><?php echo $error; ?></div>
    <?php endif; ?>
    
    <div class="row mt-4">
        <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    Menu de Opções
                </div>
                <div class="card-body">
                    <ul class="list-group">
                        <?php if (isAdmin()): ?>
                            <a href="create_user.php" class="list-group-item list-group-item-action">
                                <i class="fas fa-user-plus"></i> Criar Novo Usuário
                            </a>
                            <a href="import_users.php" class="list-group-item list-group-item-action">
                                <i class="fas fa-cloud-download-alt"></i> Importar Usuários
                            </a>
                        <?php endif; ?>
                        <a href="change_password.php" class="list-group-item list-group-item-action">
                            <i class="fas fa-key"></i> Alterar Senha
                        </a>
                        <a href="logout.php" class="list-group-item list-group-item-action text-danger">
                            <i class="fas fa-sign-out-alt"></i> Sair
                        </a>
                    </ul>
                </div>
            </div>
        </div>
        
        <?php if (isAdmin()): ?>
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    Usu�rios Samba
                </div>
                <div class="card-body">
                    <?php if (empty($users)): ?>
                        <p>Nenhum usu�rio encontrado.</p>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Nome de Usu�rio</th>
                                        <th>A��es</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($users as $username): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($username); ?></td>
                                        <td>
                                            <a href="user_info.php?username=<?php echo urlencode($username); ?>" class="btn btn-sm btn-info">
                                                <i class="fas fa-info-circle"></i> Detalhes
                                            </a>
                                            <a href="change_password.php?username=<?php echo urlencode($username); ?>" class="btn btn-sm btn-warning">
                                                <i class="fas fa-key"></i> Senha
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php endif; ?>
    </div>
</div>

<?php include 'includes/footer.php'; ?>

/**
 * LOGIN.PHP - P�gina de login
 */
<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Verificar se o usu�rio j� est� logado
if (isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$error = '';

// Processar o formul�rio de login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        $error = 'Por favor, preencha todos os campos.';
    } else {
        // Verificar as credenciais no banco de dados
        $db = connectDB();
        $stmt = $db->prepare("SELECT id, username, password FROM admins WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password'])) {
            // Login bem-sucedido
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = true;
            
            // Atualizar data do �ltimo login
            $updateStmt = $db->prepare("UPDATE admins SET last_login = NOW() WHERE id = :id");
            $updateStmt->bindParam(':id', $user['id']);
            $updateStmt->execute();
            
            // Registrar atividade
            logActivity($user['id'], 'login', 'Login bem-sucedido');
            
            header('Location: index.php');
            exit;
        } else {
            $error = 'Nome de usu�rio ou senha incorretos.';
        }
    }
}

// Incluir o cabe�alho
include 'includes/header.php';
?>

<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h4 class="text-center">Login do Administrador</h4>
                </div>
                <div class="card-body">
                    <?php if (!empty($error)): ?>
                        <div class="alert alert-danger"><?php echo $error; ?></div>
                    <?php endif; ?>
                    
                    <form method="post" action="">
                        <div class="mb-3">
                            <label for="username" class="form-label">Nome de Usu�rio</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Senha</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary">Entrar</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<?php include 'includes/footer.php'; ?>

/**
 * CREATE_USER.PHP - P�gina para criar novos usu�rios Samba
 */
<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Verificar se o usu�rio est� logado e � administrador
if (!isLoggedIn() || !isAdmin()) {
    header('Location: login.php');
    exit;
}

$message = '';
$error = '';

// Inicializar o gerenciador de usu�rios Samba
$sambaManager = new SambaUserManager($config);

// Processar o formul�rio de cria��o de usu�rio
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $fullName = $_POST['full_name'] ?? '';
    $email = $_POST['email'] ?? '';
    
    if (empty($username) || empty($password)) {
        $error = 'Por favor, preencha os campos obrigat�rios (usu�rio e senha).';
    } else {
        try {
            // Criar o usu�rio no Samba
            $sambaManager->createUser($username, $password, $fullName, $email);
            
            // Registrar no banco de dados
            $db = connectDB();
            $stmt = $db->prepare("
                INSERT INTO samba_users (username, full_name, email)
                VALUES (:username, :full_name, :email)
            ");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':full_name', $fullName);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            // Registrar atividade
            logActivity($_SESSION['user_id'], 'create_user', "Usu�rio '{$username}' criado com sucesso.");
            
            $message = "Usu�rio '{$username}' criado com sucesso!";
        } catch (Exception $e) {
            $error = 'Erro ao criar usu�rio: ' . $e->getMessage();
        }
    }
}

// Incluir o cabe�alho
include 'includes/header.php';
?>

<div class="container mt-4">
    <h1>Criar Novo Usu�rio Samba</h1>
    
    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="index.php">In�cio</a></li>
            <li class="breadcrumb-item active" aria-current="page">Criar Usu�rio</li>
        </ol>
    </nav>
    
    <?php if (!empty($message)): ?>
        <div class="alert alert-success"><?php echo $message; ?></div>
    <?php endif; ?>
    
    <?php if (!empty($error)): ?>
        <div class="alert alert-danger"><?php echo $error; ?></div>
    <?php endif; ?>
    
    <div class="card">
        <div class="card-header">
            Formul�rio de Cria��o de Usu�rio
        </div>
        <div class="card-body">
            <form method="post" action="">
                <div class="mb-3">
                    <label for="password" class="form-label">Senha <span class="text-danger">*</span></label>
                    <input type="password" class="form-control" id="password" name="password" required>
                    <small class="form-text text-muted">Use uma senha forte com pelo menos 8 caracteres.</small>
                </div>
                
                <div class="mb-3">
                    <label for="full_name" class="form-label">Nome Completo</label>
                    <input type="text" class="form-control" id="full_name" name="full_name">
                </div>
                
                <div class="mb-3">
                    <label for="email" class="form-label">E-mail</label>
                    <input type="email" class="form-control" id="email" name="email">
                </div>
                
                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                    <a href="index.php" class="btn btn-secondary">Cancelar</a>
                    <button type="submit" class="btn btn-primary">Criar Usu�rio</button>
                </div>
            </form>
        </div>
    </div>
</div>

<?php include 'includes/footer.php'; ?>

/**
 * CHANGE_PASSWORD.PHP - P�gina para alterar senhas de usu�rios
 */
<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Verificar se o usu�rio est� logado
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

$message = '';
$error = '';

// Ensure PHP block is properly closed before HTML
?>

<div class="mb-3">
    <label for="username" class="form-label">Nome de Usuário <span class="text-danger">*</span></label>
    <input type="text" class="form-control" id="username" name="username" required>
    <small class="form-text text-muted">Use apenas letras minúsculas, números e sublinhado.</small>
</div>

<div class="mb-3">
    <label for="password" class="form-label">Senha</label>