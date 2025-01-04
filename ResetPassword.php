<?php
/*
Plugin Name: Reset Password Endpoint
Description: Crea un endpoint para resetear el password
Version: 1.0
Author: Sergio Bernabé
*/

add_action('rest_api_init', function () {
    register_rest_route('custom/v1', '/reset-password', array(
        'methods' => 'POST',
        'callback' => 'custom_reset_password',
    ));

    register_rest_route('custom/v1', '/update-password', array(
        'methods' => 'POST',
        'callback' => 'custom_update_password',
    ));
});

function custom_reset_password($request) {
    $email = sanitize_email($request['email']);
    if (!is_email($email)) {
        return new WP_Error('invalid_email', 'Por favor, introduce una dirección de correo válida.', array('status' => 400));
    }

    $user = get_user_by('email', $email);
    if (!$user) {
        return new WP_Error('email_not_found', 'No existe una cuenta con este correo.', array('status' => 404));
    }

    // Generar un token seguro
    $token = wp_generate_password(32, false);

    // Guardar el token como meta del usuario
    update_user_meta($user->ID, 'password_reset_token', $token);

    // Crear el enlace de restablecimiento
    $frontend_url = 'https://tu-front-url.com/reset-password'; // Cambia esto por tu URL
    $reset_link = add_query_arg(['token' => $token, 'user_id' => $user->ID], $frontend_url);

    // Enviar correo de restablecimiento
    $mail_sent = wp_mail(
        $email, 
        'Restablecer contraseña', 
        "Usa este enlace para restablecer tu contraseña: $reset_link"
    );

    if ($mail_sent) {
        return rest_ensure_response(['message' => 'Correo de recuperación enviado.']);
    } else {
        return new WP_Error('email_failed', 'No se pudo enviar el correo.', array('status' => 500));
    }
}

function custom_update_password($request) {
    $user_id = intval($request['user_id']);
    $token = sanitize_text_field($request['token']);
    $new_password = sanitize_text_field($request['password']);

    if (!$user_id || !$token || !$new_password) {
        return new WP_Error('missing_data', 'Faltan datos para actualizar la contraseña.', array('status' => 400));
    }

    $saved_token = get_user_meta($user_id, 'password_reset_token', true);

    if (!$saved_token || !hash_equals($saved_token, $token)) {
        return new WP_Error('invalid_token', 'El token no es válido o ha expirado.', array('status' => 400));
    }

    // Actualizar la contraseña del usuario
    wp_set_password($new_password, $user_id);

    // Eliminar el token una vez usado
    delete_user_meta($user_id, 'password_reset_token');

    return rest_ensure_response(['message' => 'Contraseña actualizada correctamente.']);
}
