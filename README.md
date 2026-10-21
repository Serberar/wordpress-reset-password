# Reset Password Endpoint para WordPress

Plugin de WordPress que añade a la API REST los endpoints necesarios para **recuperar la contraseña** desde una app externa (por ejemplo, un frontend en React).

## Endpoints

| Método | Ruta | Qué hace |
|---|---|---|
| `POST` | `/wp-json/custom/v1/reset-password` | Recibe `email`, genera un token seguro, lo guarda en el usuario y envía por correo el enlace para cambiar la contraseña. |
| `POST` | `/wp-json/custom/v1/update-password` | Recibe `reset` (el token del enlace) y `password` (la nueva contraseña) y la cambia si el token es válido. |

Errores: `400` si el email o el token no son válidos o faltan datos, `404` si no hay ninguna cuenta con ese correo y `500` si no se pudo enviar el email.

## Instalación

1. Copia `ResetPassword.php` en `wp-content/plugins/reset-password/`.
2. Actívalo en **Plugins** dentro del panel de WordPress.
3. Cambia `$frontend_url` (ahora `http://localhost:3000/password`) por la página de tu frontend que recibe el token.

## Tecnologías

PHP y la API REST de WordPress (`wp_mail`, `user_meta`).

## Autor

Sergio Bernabé
