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

// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

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
        'host' => getenv('SAMBA_HOST'),
        'admin_user' => getenv('SAMBA_ADMIN_USER'),
        'admin_password' => getenv('SAMBA_ADMIN_PASSWORD'),
        'domain' => getenv('SAMBA_DOMAIN'),
    ],
    'db' => [
        'host' => (getenv('DB_HOST') && getenv('DB_HOST') !== 'localhost') ? getenv('DB_HOST') : '127.0.0.1',
        'username' => getenv('DB_USERNAME') ?: 'root',
        'password' => getenv('DB_PASSWORD') ?: '',
        'database' => getenv('DB_DATABASE') ?: 'samba',
    ],
    'oauth' => [
        'facebook' => [
            'app_id' => getenv('FACEBOOK_APP_ID'),
            'app_secret' => getenv('FACEBOOK_APP_SECRET'),
            'redirect_uri' => getenv('FACEBOOK_REDIRECT_URI'),
        ],
        'google' => [
            'client_id' => getenv('GOOGLE_CLIENT_ID'),
            'client_secret' => getenv('GOOGLE_CLIENT_SECRET'),
            'redirect_uri' => getenv('GOOGLE_REDIRECT_URI'),
        ],
        'microsoft' => [
            'client_id' => getenv('MICROSOFT_CLIENT_ID'),
            'client_secret' => getenv('MICROSOFT_CLIENT_SECRET'),
            'redirect_uri' => getenv('MICROSOFT_REDIRECT_URI'),
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