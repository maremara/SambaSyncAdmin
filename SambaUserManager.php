<?php
/**
 * SAMBA USER MANAGER - Handles Samba user operations via SSH
 */
class SambaUserManager {
    private $config;

    public function __construct($config) {
        $this->config = $config;
        if (!function_exists('ssh2_connect')) {
            throw new Exception('Extensão SSH2 não está instalada. Verifique sua configuração PHP.');
        }
    }

    /**
     * Executes a command on the remote Samba server via SSH.
     *
     * @param string $command The command to execute.
     * @return array The output of the command, or an empty array on failure.
     * @throws Exception If there is an error connecting or executing the command.
     */
    private function executeSambaCommand($command) {
        $connection = @ssh2_connect($this->config['samba']['host'], 22); // Using @ to suppress warnings
        if (!$connection) {
            throw new Exception("Não foi possível conectar ao servidor Samba via SSH: {$this->config['samba']['host']}");
        }

        $authResult = @ssh2_auth_password(
            $connection,
            $this->config['samba']['admin_user'],
            $this->config['samba']['admin_password']
        );
        if (!$authResult) {
            throw new Exception("Falha na autenticação SSH para o usuário: {$this->config['samba']['admin_user']} no host: {$this->config['samba']['host']}");
        }

        $stream = @ssh2_exec($connection, $command); // Using @ to suppress warnings
        if (!$stream) {
            throw new Exception("Falha ao executar o comando SSH: $command no host: {$this->config['samba']['host']}");
        }

        stream_set_blocking($stream, true);
        $output = stream_get_contents($stream);
        $errorStream = ssh2_fetch_stream($stream, SSH2_STREAM_STDERR);
        if ($errorStream) {
            stream_set_blocking($errorStream, true);
            $errorOutput = stream_get_contents($errorStream);
            if (!empty($errorOutput)) {
                error_log("Erro do servidor Samba: $errorOutput"); // Log the error
            }
            fclose($errorStream);
        }
        fclose($stream);

        $output = explode("\n", trim($output));
        // Remove empty lines and lines with only whitespace
        $output = array_filter($output, function($line) {
            return !empty(trim($line));
        });

        // Basic error checking (improve as needed)
        foreach ($output as $line) {
            if (stripos($line, 'error') !== false || stripos($line, 'failed') !== false) {
                error_log("Possível erro no comando Samba: $line");
            }
        }

        return $output;
    }


    /**
     * Checks if a user exists in Samba.
     *
     * @param string $username The username to check.
     * @return bool True if the user exists, false otherwise.
     * @throws Exception If there is an error executing the command.
     */
    public function userExists($username) {
        try {
            $command = "pdbedit -L | grep -i \"^{$username}:\"";
            $output = $this->executeSambaCommand($command);
            return !empty($output);
        } catch (Exception $e) {
            error_log("Erro ao verificar se o usuário existe: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Creates a new Samba user.
     *
     * @param string $username The username.
     * @param string $password The password.
     * @param string $fullName (Optional) The full name of the user.
     * @param string $email (Optional) The email of the user.
     * @return bool True on success, false on failure.
     * @throws Exception If there is an error creating the user.
     */
    public function createUser($username, $password, $fullName = '', $email = '') {
        if ($this->userExists($username)) {
            throw new Exception("Usuário '{$username}' já existe no servidor Samba");
        }

        // Create the user in the system (Linux)
        try {
            $addUserCommand = "sudo useradd -m -s /bin/bash {$username}";
            $this->executeSambaCommand($addUserCommand);
        } catch (Exception $e) {
            throw new Exception("Erro ao criar usuário no sistema: " . $e->getMessage());
        }

        // Set the user's password in the system
        try {
            $setUnixPasswordCmd = "echo \"{$username}:{$password}\" | sudo chpasswd";
            $this->executeSambaCommand($setUnixPasswordCmd);
        } catch (Exception $e) {
            // If setting the Unix password fails, you might want to delete the user
            $this->executeSambaCommand("sudo userdel -f $username");
            throw new Exception("Erro ao definir a senha do usuário no sistema: " . $e->getMessage());
        }

        // Add the user to Samba
        try {
            $addSambaCommand = "echo -ne '{$password}\n{$password}\n' | sudo smbpasswd -a {$username}";
            $this->executeSambaCommand($addSambaCommand);
        } catch (Exception $e) {
            // Cleanup if Samba user creation fails
            $this->executeSambaCommand("sudo userdel -f $username");
            $this->executeSambaCommand("sudo smbpasswd -x $username");
            throw new Exception("Erro ao adicionar usuário ao Samba: " . $e->getMessage());
        }

        // Enable the user in Samba
        try {
            $enableCommand = "sudo smbpasswd -e {$username}";
            $this->executeSambaCommand($enableCommand);
        } catch (Exception $e) {
            throw new Exception("Erro ao habilitar usuário no Samba: " . $e->getMessage());
        }

        return true;
    }


    /**
     * Gets information about a Samba user.
     *
     * @param string $username The username to get information for.
     * @return array An associative array of user information.
     * @throws Exception If the user does not exist or there is an error retrieving information.
     */
    public function getUserInfo($username) {
        if (!$this->userExists($username)) {
            throw new Exception("Usuário '{$username}' não existe no servidor Samba");
        }

        $command = "sudo pdbedit -L -v {$username}";
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
     * Changes the password of a Samba user.
     *
     * @param string $username The username.
     * @param string $newPassword The new password.
     * @return bool True on success, false on failure.
     * @throws Exception If the user does not exist or there is an error changing the password.
     */
    public function changePassword($username, $newPassword) {
        if (!$this->userExists($username)) {
            throw new Exception("Usuário '{$username}' não existe no servidor Samba");
        }

        // Change password in the system
        try {
            $changeUnixPasswordCmd = "echo \"{$username}:{$newPassword}\" | sudo chpasswd";
            $this->executeSambaCommand($changeUnixPasswordCmd);
        } catch (Exception $e) {
            throw new Exception("Erro ao alterar a senha do usuário no sistema: " . $e->getMessage());
        }

        // Change password in Samba
        try {
            $changeSambaPasswordCmd = "echo -ne '{$newPassword}\n{$newPassword}\n' | sudo smbpasswd {$username}";
            $this->executeSambaCommand($changeSambaPasswordCmd);
        } catch (Exception $e) {
            throw new Exception("Erro ao alterar a senha do usuário no Samba: " . $e->getMessage());
        }

        return true;
    }

    /**
     * Lists all Samba users.
     *
     * @return array An array of usernames.
     * @throws Exception If there is an error listing users.
     */
    public function listUsers() {
        $command = "sudo pdbedit -L";
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
?>