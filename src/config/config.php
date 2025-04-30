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

require_once __DIR__ . '/../../vendor/autoload.php';

use Dotenv\Dotenv;

// Carregar variáveis do arquivo .env
$dotenv = Dotenv::createImmutable(__DIR__ . '/../../');
$dotenv->load();


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
        'host' => $_ENV['SAMBA_HOST'],
        'admin_user' => $_ENV['SAMBA_ADMIN_USER'],
        'admin_password' => $_ENV['SAMBA_ADMIN_PASSWORD'],
        'domain' => $_ENV['SAMBA_DOMAIN'],
    ],
    'db' => [
        'host' => ($_ENV['DB_HOST'] && $_ENV['DB_HOST'] !== 'localhost') ? $_ENV['DB_HOST'] : '127.0.0.1',
        'username' => $_ENV['DB_USERNAME'] ?: 'root',
        'password' => $_ENV['DB_PASSWORD'] ?: '',
        'database' => $_ENV['DB_DATABASE'] ?: 'samba',
    ],
    'oauth' => [
        'facebook' => [
            'app_id' => $_ENV['FACEBOOK_APP_ID'],
            'app_secret' => $_ENV['FACEBOOK_APP_SECRET'],
            'redirect_uri' => $_ENV['FACEBOOK_REDIRECT_URI'],
        ],
        'google' => [
            'client_id' => $_ENV['GOOGLE_CLIENT_ID'],
            'client_secret' => $_ENV['GOOGLE_CLIENT_SECRET'],
            'redirect_uri' => $_ENV['GOOGLE_REDIRECT_URI'],
        ],
        'microsoft' => [
            'client_id' => $_ENV['MICROSOFT_CLIENT_ID'],
            'client_secret' => $_ENV['MICROSOFT_CLIENT_SECRET'],
            'redirect_uri' => $_ENV['MICROSOFT_REDIRECT_URI'],
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