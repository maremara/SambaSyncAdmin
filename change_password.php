<?php
/**
 * CHANGE_PASSWORD.PHP - P�gina para alterar senhas de usu�rios
 */
session_start();
require_once 'config.php';
require_once 'functions.php';

// Verificar se o usu�rio est� logado
if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

$message = '';
$error = '';

// Ensure PHP block is properly closed before HTML
?>

<div class="mb-3">
    <label for="username" class="form-label">Nome de Usuário <span class="text-danger">*</span></label>
    <input type="text" class="form-control" id="username" name="username" required>
    <small class="form-text text-muted">Use apenas letras minúsculas, números e sublinhado.</small>
</div>

<div class="mb-3">
    <label for="password" class="form-label">Senha</label>