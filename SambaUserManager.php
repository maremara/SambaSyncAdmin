<?php
/**
 * SAMBA USER MANAGER - Handles Samba user operations
 */
class SambaUserManager {
    private $config;

    public function __construct($config) {
        $this->config = $config;
    }

    /**
     * Create a new Samba user
     */
    public function createUser($username, $password, $fullName = '', $email = '') {
        // Validate inputs
        if (empty($username) || empty($password)) {
            throw new Exception("Username and password are required");
        }

        // Execute Samba command to create user
        $cmd = "sudo smbpasswd -a {$username}";
        $output = [];
        $return_var = 0;
        
        exec("echo '{$password}\n{$password}\n' | {$cmd}", $output, $return_var);

        if ($return_var !== 0) {
            throw new Exception("Failed to create Samba user: " . implode("\n", $output));
        }

        return true;
    }

    /**
     * List all Samba users
     */
    public function listUsers() {
        $output = [];
        exec("sudo pdbedit -L", $output);
        
        $users = [];
        foreach ($output as $line) {
            if (preg_match('/^([^:]+):/', $line, $matches)) {
                $users[] = $matches[1];
            }
        }

        return $users;
    }

    /**
     * Change user password
     */
    public function changePassword($username, $newPassword) {
        if (empty($username) || empty($newPassword)) {
            throw new Exception("Username and password are required");
        }

        $cmd = "sudo smbpasswd {$username}";
        $output = [];
        $return_var = 0;
        
        exec("echo '{$newPassword}\n{$newPassword}\n' | {$cmd}", $output, $return_var);

        if ($return_var !== 0) {
            throw new Exception("Failed to change password: " . implode("\n", $output));
        }

        return true;
    }
}
