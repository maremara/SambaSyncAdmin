<?php
/**
 * LOGOUT.PHP - Finaliza a sessão do usuário
 */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Registrar atividade antes de destruir sessão
require_once 'config.php';
require_once 'functions.php';

if (isset($_SESSION['user_id'])) {
    logActivity($_SESSION['user_id'], 'logout', 'Logout realizado');
}

// Limpa e destrói a sessão
$_SESSION = [];
session_unset();
session_destroy();

// Redireciona para o login
header('Location: login.php');
exit;
