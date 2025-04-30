<?php
/**
 * ChangePasswordController - Handles password change logic
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../utils/functions.php';
require_once __DIR__ . '/../models/SambaUserManager.php';

class ChangePasswordController {
    private $db;
    private $message = '';
    private $error = '';

    public function __construct() {
        $this->db = connectDB();
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    public function handleRequest() {
        if (!isLoggedIn()) {
            header('Location: login.php');
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->processForm();
        }
    }

    private function processForm() {
        if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
            $this->error = 'Invalid CSRF token. Please try again.';
            return;
        }

        $username = sanitizeInput($_POST['username'] ?? '');
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        if (!validateUsername($username)) {
            $this->error = 'Invalid username format. Use only lowercase letters, numbers, and underscores (3-20 characters).';
        } elseif (!validatePassword($new_password)) {
            $this->error = 'New password must be at least 8 characters long and include uppercase, lowercase letters, and numbers.';
        } elseif ($new_password !== $confirm_password) {
            $this->error = 'New password and confirmation do not match.';
        } else {
            try {
                $stmt = $this->db->prepare('SELECT password FROM samba_users WHERE username = :username');
                $stmt->bindParam(':username', $username);
                $stmt->execute();
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$user) {
                    $this->error = 'User not found.';
                } elseif (!verifyPassword($current_password, $user['password'])) {
                    $this->error = 'Current password is incorrect.';
                } else {
                    $new_hash = hashPassword($new_password);
                    $updateStmt = $this->db->prepare('UPDATE samba_users SET password = :password WHERE username = :username');
                    $updateStmt->bindParam(':password', $new_hash);
                    $updateStmt->bindParam(':username', $username);
                    $updateStmt->execute();

                    $this->message = 'Password changed successfully.';
                    logActivity($_SESSION['user_id'], 'change_password', "Password changed for user $username");
                }
            } catch (PDOException $e) {
                $this->error = 'Database error: ' . htmlspecialchars($e->getMessage());
            }
        }
    }

    public function getMessage() {
        return $this->message;
    }

    public function getError() {
        return $this->error;
    }
}
?>
