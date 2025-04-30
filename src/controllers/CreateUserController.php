<?php
/**
 * CreateUserController - Handles user creation logic
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../utils/functions.php';
require_once __DIR__ . '/../models/SambaUserManager.php';

class CreateUserController {
    private $db;
    private $sambaManager;
    private $message = '';
    private $error = '';
    private $formData = [
        'username' => '',
        'full_name' => '',
        'email' => ''
    ];

    public function __construct() {
        $this->db = connectDB();
        $this->sambaManager = new SambaUserManager($GLOBALS['config']);
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    public function handleRequest() {
        if (!isLoggedIn() || !isAdmin()) {
            header('Location: login.php');
            exit;
        }

        // Check inactivity timeout
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
            session_unset();
            session_destroy();
            header('Location: login.php?expired=1');
            exit;
        }
        $_SESSION['last_activity'] = time();

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->processForm();
        }
    }

    private function processForm() {
        if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
            $this->error = 'Erro de segurança: token inválido. Tente novamente.';
            return;
        }

        $username = sanitizeInput($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        $fullName = sanitizeInput($_POST['full_name'] ?? '');
        $email = sanitizeInput($_POST['email'] ?? '');

        $this->formData = [
            'username' => $username,
            'full_name' => $fullName,
            'email' => $email
        ];

        if (empty($username)) {
            $this->error = 'Nome de usuário é obrigatório.';
        } elseif (!validateUsername($username)) {
            $this->error = 'Nome de usuário inválido. Use apenas letras minúsculas, números e underscore (3-20 caracteres).';
        } elseif (empty($password)) {
            $this->error = 'Senha é obrigatória.';
        } elseif (!validatePassword($password)) {
            $this->error = 'Senha inválida. Use pelo menos 8 caracteres, incluindo maiúsculas, minúsculas e números.';
        } elseif ($password !== $confirmPassword) {
            $this->error = 'As senhas não coincidem.';
        } elseif (!empty($email) && !validateEmail($email)) {
            $this->error = 'E-mail inválido.';
        } else {
            try {
                $checkStmt = $this->db->prepare("SELECT id FROM samba_users WHERE username = :username");
                $checkStmt->bindParam(':username', $username);
                $checkStmt->execute();

                if ($checkStmt->rowCount() > 0) {
                    $this->error = "Usuário '{$username}' já existe no banco de dados.";
                } else {
                    $this->sambaManager->createUser($username, $password, $fullName, $email);

                    $stmt = $this->db->prepare("
                        INSERT INTO samba_users (username, full_name, email)
                        VALUES (:username, :full_name, :email)
                    ");
                    $stmt->bindParam(':username', $username);
                    $stmt->bindParam(':full_name', $fullName);
                    $stmt->bindParam(':email', $email);
                    $stmt->execute();

                    logActivity($_SESSION['user_id'], 'create_user', "Usuário '{$username}' criado com sucesso.");

                    $this->message = "Usuário '{$username}' criado com sucesso!";

                    $this->formData = [
                        'username' => '',
                        'full_name' => '',
                        'email' => ''
                    ];
                }
            } catch (Exception $e) {
                $this->error = 'Erro ao criar usuário: ' . $e->getMessage();
            }
        }
    }

    public function getMessage() {
        return $this->message;
    }

    public function getError() {
        return $this->error;
    }

    public function getFormData() {
        return $this->formData;
    }
}
?>
