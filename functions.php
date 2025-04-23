<?php
/**
 * FUNCTIONS.PHP - Funções de segurança e validação para o sistema
 */

/**
 * Sanitiza e valida uma string de entrada
 *
 * @param string $data Dados a serem sanitizados
 * @return string Dados sanitizados
 */
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

/**
 * Valida um endereço de e-mail
 *
 * @param string $email E-mail a ser validado
 * @return bool True se o e-mail for válido, false caso contrário
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Valida uma URL
 *
 * @param string $url URL a ser validada
 * @return bool True se a URL for válida, false caso contrário
 */
function validateURL($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

/**
 * Valida um nome de usuário
 * Apenas letras, números e underscores, 3-20 caracteres
 *
 * @param string $username Nome de usuário a ser validado
 * @return bool True se o nome de usuário for válido, false caso contrário
 */
function validateUsername($username) {
    return preg_match('/^[a-z0-9_]{3,20}$/', $username) === 1;
}

/**
 * Valida uma senha
 * Pelo menos 8 caracteres, uma letra maiúscula, uma letra minúscula, um número
 *
 * @param string $password Senha a ser validada
 * @return bool True se a senha for válida, false caso contrário
 */
function validatePassword($password) {
    // Pelo menos 8 caracteres
    if (strlen($password) < 8) {
        return false;
    }
    
    // Verificar se contém pelo menos uma letra maiúscula
    if (!preg_match('/[A-Z]/', $password)) {
        return false;
    }
    
    // Verificar se contém pelo menos uma letra minúscula
    if (!preg_match('/[a-z]/', $password)) {
        return false;
    }
    
    // Verificar se contém pelo menos um número
    if (!preg_match('/[0-9]/', $password)) {
        return false;
    }
    
    return true;
}

/**
 * Gera um hash seguro de senha usando bcrypt
 *
 * @param string $password Senha a ser hasheada
 * @return string Hash da senha
 */
function hashPassword($password) {
    // Custo 12 é um bom equilíbrio entre segurança e desempenho
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Verifica se uma senha corresponde a um hash
 *
 * @param string $password Senha a ser verificada
 * @param string $hash Hash armazenado
 * @return bool True se a senha for válida, false caso contrário
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Gera um token CSRF
 *
 * @return string Token CSRF
 */
function generateCSRFToken() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verifica se um token CSRF é válido
 *
 * @param string $token Token a ser verificado
 * @return bool True se o token for válido, false caso contrário
 */
function verifyCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || $token !== $_SESSION['csrf_token']) {
        return false;
    }
    return true;
}

/**
 * Registra atividade no log
 *
 * @param int $userId ID do usuário ou admin
 * @param string $action Ação realizada
 * @param string $description Descrição da ação
    if (!$db) {
        throw new Exception("Erro ao conectar ao banco de dados.");
    }
 */

 function logActivity($adminId, $action, $description = null) {
    if (!$adminId) {
        error_log("Tentativa de log de atividade com admin_id inválido.");
        return false;
    }

    try {
        $db = connectDB();
        $stmt = $db->prepare("INSERT INTO activity_logs (admin_id, action, description, ip_address, user_agent, log_time)
                              VALUES (:admin_id, :action, :description, :ip_address, :user_agent, NOW())");
        $stmt->execute([
            ':admin_id'   => $adminId,
            ':action'     => $action,
            ':description'=> $description,
            ':ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN',
            ':user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN'
        ]);
        return true;
    } catch (PDOException $e) {
        error_log("Erro ao registrar atividade: " . $e->getMessage());
        return false;
    }
}

/**
 * Verifica se o usuário está logado
 *
 * @return bool True se o usuário estiver logado, false caso contrário
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

/**
 * Verifica se o usuário logado é um administrador
 *
 * @return bool True se o usuário for administrador, false caso contrário
 */
function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
}

/**
 * Força o uso de HTTPS
 */
function forceHTTPS() {
    if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
        $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        header("Location: $redirect");
        exit;
    }
}

/**
 * Define cabeçalhos de segurança HTTP
 */
function setSecurityHeaders() {
    // Impedir que o navegador detecte o tipo MIME do conteúdo de forma automática
    header("X-Content-Type-Options: nosniff");
    
    // Habilitar proteção XSS no navegador
    header("X-XSS-Protection: 1; mode=block");
    
    // Impedir que o site seja aberto em um iframe (proteção contra clickjacking)
    header("X-Frame-Options: DENY");
    
    // Política de segurança de conteúdo (CSP)
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self';");
    
    // Strict-Transport-Security (HSTS)
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
    
    // Referrer Policy
    header("Referrer-Policy: same-origin");
}

/**
 * Impede ataques de fixação de sessão
 */
function regenerateSession() {
    session_regenerate_id(true);
}