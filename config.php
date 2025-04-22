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

 
// Iniciar sessão
// Habilitar output buffering para segurança
/**
ob_start();

// Configurações de sessão segura
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 1800); // 30 minutos
**/
<?php
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.gc_maxlifetime', 1800); // 30 minutos
    session_start();
} else {
    // A sessão já foi iniciada, não é possível mudar as configurações
    error_log('Sessão já foi iniciada. Não foi possível definir novas configurações de sessão.');
}

session_start();

// Configuração
$config = [
    'samba' => [
        'host' => 'localhost',
        'admin_user' => 'root',
        'admin_password' => getenv('SAMBA_ADMIN_PASSWORD') ?: 'default_password',
        'domain' => 'EXEMPLO.LOCAL',
    ],
    'db' => [
        'host' => 'localhost',
        'username' => 'root',
        'password' => '',
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

/**
 * Classe para gerenciar usuários Samba
 */
class SambaUserManager {
    // Removed unused $config property
    
    public function __construct($config) {
        $this->config = $config;
    }
    
    /**
     * Executa um comando no servidor Samba
     */
    private function executeSambaCommand($command) {
        $output = [];
        $returnCode = 0;
        
        exec($command, $output, $returnCode);
        
        if ($returnCode !== 0) {
            throw new Exception("Erro ao executar comando Samba: " . implode("\n", $output));
        }
        
        return $output;
    }
    
    /**
     * Verifica se um usuário existe no Samba
     */
    public function userExists($username) {
        try {
            $command = "pdbedit -L | grep -i \"^{$username}:\"";
            $output = $this->executeSambaCommand($command);
            return !empty($output);
        } catch (Exception $e) {
            error_log($e->getMessage()); // Log the exception message
            return false;
        }
    }
    
    /**
     * Cria um novo usuário no Samba
    public function createUser($username, $password) {
        if ($this->userExists($username)) {
            throw new Exception("Usuário '{$username}' já existe no servidor Samba");
        }
        
        // Comando para adicionar usuário ao sistema Unix primeiro (necessário para Samba)
        $addUserCommand = "useradd -m -s /bin/bash {$username}";
        $this->executeSambaCommand($addUserCommand);
        
        // Optionally log the creation of the user
        error_log("User '{$username}' created successfully.");
        $this->executeSambaCommand($addUserCommand);
        
        // Definir senha no sistema Unix
        $setUnixPasswordCmd = "echo \"{$username}:{$password}\" | chpasswd";
        $this->executeSambaCommand($setUnixPasswordCmd);
        
        // Adicionar usuário ao Samba
        $addSambaCommand = "echo -ne '{$password}\n{$password}\n' | smbpasswd -a {$username}";
        $this->executeSambaCommand($addSambaCommand);
        
        // Habilitar usuário no Samba
        $enableCommand = "smbpasswd -e {$username}";
        $this->executeSambaCommand($enableCommand);
        
        return true;
    }
    
    /**
     * Consulta informações de um usuário no Samba
     */
    public function getUserInfo($username) {
        if (!$this->userExists($username)) {
            throw new Exception("Usuário '{$username}' não existe no servidor Samba");
        }
        
        $command = "pdbedit -L -v {$username}";
        $output = $this->executeSambaCommand($command);
        
        $userInfo = [];
        foreach ($output as $line) {
            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $userInfo[trim($key)] = trim($value);
            }
        }
        
        return $userInfo;
    }
    
    /**
     * Altera a senha de um usuário no Samba
     */
    public function changePassword($username, $newPassword) {
        if (!$this->userExists($username)) {
            throw new Exception("Usuário '{$username}' não existe no servidor Samba");
        }
        
        // Alterar senha no sistema Unix
        $changeUnixPasswordCmd = "echo \"{$username}:{$newPassword}\" | chpasswd";
        $this->executeSambaCommand($changeUnixPasswordCmd);
        
        // Alterar senha no Samba (necessita ser root ou ter permissões)
        $changeSambaPasswordCmd = "echo -ne '{$newPassword}\n{$newPassword}\n' | smbpasswd {$username}";
        $this->executeSambaCommand($changeSambaPasswordCmd);
        
        return true;
    }
    
    /**
     * Lista todos os usuários do Samba
     */
    public function listUsers() {
        $command = "pdbedit -L";
        $output = $this->executeSambaCommand($command);
        
        $users = [];
        foreach ($output as $line) {
            if (strpos($line, ':') !== false) {
                $parts = explode(':', $line);
                $users[] = $parts[0];
            }
        }
        
        return $users;
    }
}

/**
 * Classe para importar dados de serviços externos
 */
class ExternalServiceImporter {
    private $config;
    private $db;
    
    public function __construct($config, $db) {
        $this->config = $config;
        $this->db = $db;
    }
    
    /**
     * Obter URL de autenticação para Facebook
     */
    public function getFacebookAuthUrl() {
        $config = $this->config['oauth']['facebook'];
        
        $params = [
            'client_id' => $config['app_id'],
            'redirect_uri' => $config['redirect_uri'],
            'scope' => 'email,public_profile',
            'response_type' => 'code',
            'state' => bin2hex(random_bytes(16))
        ];
        
        $_SESSION['oauth_state'] = $params['state'];
        
        return 'https://www.facebook.com/v12.0/dialog/oauth?' . http_build_query($params);
    }
    
    /**
     * Processar callback do Facebook e obter dados do usuário
     */
    public function processFacebookCallback($code) {
        $config = $this->config['oauth']['facebook'];
        
        // Trocar o código por um token de acesso
        $tokenUrl = 'https://graph.facebook.com/v12.0/oauth/access_token';
        $params = [
            'client_id' => $config['app_id'],
            'client_secret' => $config['app_secret'],
            'redirect_uri' => $config['redirect_uri'],
            'code' => $code
        ];
        
        $response = file_get_contents($tokenUrl . '?' . http_build_query($params));
        $tokenData = json_decode($response, true);
        
        if (!isset($tokenData['access_token'])) {
            throw new Exception('Erro ao obter token de acesso do Facebook');
        }
        
        // Obter dados do usuário
        $userUrl = 'https://graph.facebook.com/v12.0/me?fields=id,name,email&access_token=' . $tokenData['access_token'];
        $userData = json_decode(file_get_contents($userUrl), true);
        
        return [
            'service' => 'facebook',
            'service_id' => $userData['id'],
            'name' => $userData['name'],
            'email' => $userData['email'] ?? '',
        ];
    }
    
    /**
     * Obter URL de autenticação para Google
     */
    public function getGoogleAuthUrl() {
        $config = $this->config['oauth']['google'];
        
        $params = [
            'client_id' => $config['client_id'],
            'redirect_uri' => $config['redirect_uri'],
            'scope' => 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
            'response_type' => 'code',
            'access_type' => 'offline',
            'state' => bin2hex(random_bytes(16))
        ];
        
        $_SESSION['oauth_state'] = $params['state'];
        
        return 'https://accounts.google.com/o/oauth2/auth?' . http_build_query($params);
    }
    
    /**
     * Processar callback do Google e obter dados do usuário
     */
    public function processGoogleCallback($code) {
        $config = $this->config['oauth']['google'];
        
        // Trocar o código por um token de acesso
        $tokenUrl = 'https://oauth2.googleapis.com/token';
        $postData = [
            'client_id' => $config['client_id'],
            'client_secret' => $config['client_secret'],
            'redirect_uri' => $config['redirect_uri'],
            'code' => $code,
            'grant_type' => 'authorization_code'
        ];
        
        $options = [
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query($postData)
            ]
        ];
        
        $context = stream_context_create($options);
        $response = file_get_contents($tokenUrl, false, $context);
        $tokenData = json_decode($response, true);
        
        if (!isset($tokenData['access_token'])) {
            throw new Exception('Erro ao obter token de acesso do Google');
        }
        
        // Obter dados do usuário
        $userUrl = 'https://www.googleapis.com/oauth2/v3/userinfo';
        $options = [
            'http' => [
                'method' => 'GET',
                'header' => 'Authorization: Bearer ' . $tokenData['access_token']
            ]
        ];
        
        $context = stream_context_create($options);
        $userData = json_decode(file_get_contents($userUrl, false, $context), true);
        
        return [
            'service' => 'google',
            'service_id' => $userData['sub'],
            'name' => $userData['name'],
            'email' => $userData['email'],
        ];
    }
    
    /**
     * Obter URL de autenticação para Microsoft (Hotmail/Outlook)
     */
    public function getMicrosoftAuthUrl() {
        $config = $this->config['oauth']['microsoft'];
        
        $params = [
            'client_id' => $config['client_id'],
            'redirect_uri' => $config['redirect_uri'],
            'scope' => 'openid profile email',
            'response_type' => 'code',
            'state' => bin2hex(random_bytes(16))
        ];
        
        $_SESSION['oauth_state'] = $params['state'];
        
        return 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' . http_build_query($params);
    }
    
    /**
     * Processar callback do Microsoft e obter dados do usuário
     */
    public function processMicrosoftCallback($code) {
        $config = $this->config['oauth']['microsoft'];
        
        // Trocar o código por um token de acesso
        $tokenUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
        $postData = [
            'client_id' => $config['client_id'],
            'client_secret' => $config['client_secret'],
            'redirect_uri' => $config['redirect_uri'],
            'code' => $code,
            'grant_type' => 'authorization_code'
        ];
        
        $options = [
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query($postData)
            ]
        ];
        
        $context = stream_context_create($options);
        $response = file_get_contents($tokenUrl, false, $context);
        $tokenData = json_decode($response, true);
        
        if (!isset($tokenData['access_token'])) {
            throw new Exception('Erro ao obter token de acesso da Microsoft');
        }
        
        // Obter dados do usuário
        $userUrl = 'https://graph.microsoft.com/v1.0/me';
        $options = [
            'http' => [
                'method' => 'GET',
                'header' => 'Authorization: Bearer ' . $tokenData['access_token']
            ]
        ];
        
        $context = stream_context_create($options);
        $userData = json_decode(file_get_contents($userUrl, false, $context), true);
        
        return [
            'service' => 'microsoft',
            'service_id' => $userData['id'],
            'name' => $userData['displayName'],
            'email' => $userData['mail'] ?? $userData['userPrincipalName'],
        ];
    }
    
    /**
     * Salvar dados do usuário importado no banco de dados
     */
    public function saveImportedUser($userData) {
        $stmt = $this->db->prepare("
            INSERT INTO imported_users (service, service_id, name, email, import_date)
            VALUES (:service, :service_id, :name, :email, NOW())
            ON DUPLICATE KEY UPDATE
            name = :name, email = :email, import_date = NOW()
        ");
        
        $stmt->bindParam(':service', $userData['service']);
        $stmt->bindParam(':service_id', $userData['service_id']);
        $stmt->bindParam(':name', $userData['name']);
        $stmt->bindParam(':email', $userData['email']);
        
        return $stmt->execute();
    }
    
    /**
     * Obter lista de usuários importados
     */
    public function getImportedUsers() {
        $stmt = $this->db->query("SELECT * FROM imported_users ORDER BY import_date DESC");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}