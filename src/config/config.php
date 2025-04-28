<?php
/**
 * Sistema de Gerenciamento de Senhas Samba
 * 
 * Este sistema permite:
 * - Criar novos usuários no servidor Samba
 * - Consultar informações de usuários existentes
 * - Alterar senhas de usuários
 * - Importar dados de usuários de serviços externos (Facebook, Instagram, Gmail, Hotmail)
 */

// Iniciar sessão (apenas uma vez, após configurar as opções)
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.gc_maxlifetime', 1800); // 30 minutos
    session_start();
} else {
    // Log a message if a session was already started elsewhere
    error_log('Sessão já estava ativa quando config.php foi incluído.');
}

// Configuração
$config = [
    'samba' => [
        'host' => '10.5.24.27', // Altere para o IP do servidor Samba
        'admin_user' => 'root',      // Usuário com permissão para executar comandos Samba
        'admin_password' => 'Q@f0rc@3$TEJAc0mVC',   // Senha do usuário SSH ou chave SSH (recomendado)
        'domain' => 'AMAN.EB.MIL.BR',
    ],
    'db' => [
        'host' => 'localhost',
        'username' => 'root',
        'password' => 'Q@f0rc@3$TEJAc0mVC',
        'database' => 'samba_users'
    ],
    'oauth' => [
        'facebook' => [
            'app_id' => 'seu_app_id_facebook',
            'app_secret' => 'seu_app_secret_facebook',
            'redirect_uri' => 'https://seu-site.com/oauth/facebook_callback.php',
        ],
        'google' => [
            'client_id' => 'seu_client_id_google',
            'client_secret' => 'seu_client_secret_google',
            'redirect_uri' => 'https://seu-site.com/oauth/google_callback.php',
        ],
        'microsoft' => [
            'client_id' => 'seu_client_id_microsoft',
            'client_secret' => 'seu_client_secret_microsoft',
            'redirect_uri' => 'https://seu-site.com/oauth/microsoft_callback.php',
        ],
    ]
];

// Conexão com o banco de dados
function connectDB() {
    global $config;
    
    try {
        $conn = new PDO(
            "mysql:host={$config['db']['host']};dbname={$config['db']['database']}",
            $config['db']['username'],
            $config['db']['password']
        );
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $conn;
    } catch(PDOException $e) {
        die("Erro de conexão: " . $e->getMessage());
    }
}