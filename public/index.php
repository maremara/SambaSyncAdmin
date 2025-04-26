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
                    Usuários Samba
                </div>
                <div class="card-body">
                    <?php if (empty($users)): ?>
                        <p>Nenhum usuário encontrado.</p>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Nome de Usuário</th>
                                        <th>Ações</th>
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