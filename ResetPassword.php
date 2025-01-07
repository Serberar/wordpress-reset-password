<?php
/*
Plugin Name: Reset Password Endpoint
Description: Crea un endpoint para resetear la contraseña
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
    $reset_token = wp_generate_password(32, false);

    // Guardar el token como meta del usuario
    update_user_meta($user->ID, 'password_reset_token', $reset_token);

    // Crear el enlace de restablecimiento con solo el nuevo nombre 'reset'
    $frontend_url = 'http://localhost:3000/password'; // Cambia esto por tu URL
    $reset_link = add_query_arg('reset', $reset_token, $frontend_url);

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
    $reset_token = sanitize_text_field($request['reset']);
    $new_password = sanitize_text_field($request['password']);

    if (!$reset_token || !$new_password) {
        return new WP_Error('missing_data', 'Faltan datos para actualizar la contraseña.', array('status' => 400));
    }

    // Buscar el usuario asociado con el token
    $user_query = new WP_User_Query([
        'meta_key' => 'password_reset_token',
        'meta_value' => $reset_token,
        'number' => 1,  // Solo obtener un usuario
    ]);

    $users = $user_query->get_results();
    if (empty($users)) {
        return new WP_Error('invalid_token', 'El enlace de restablecimiento no es válido o ha expirado.', array('status' => 400));
    }

    // Obtener el primer usuario encontrado
    $user = $users[0];
    $user_id = $user->ID;

    // Actualizar la contraseña del usuario
    wp_set_password($new_password, $user_id);

    // Eliminar el token una vez usado
    delete_user_meta($user_id, 'password_reset_token');

    return rest_ensure_response(['message' => 'Contraseña actualizada correctamente.']);
}
