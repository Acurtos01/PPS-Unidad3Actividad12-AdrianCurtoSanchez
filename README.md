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

Accedemos al contendedor de la base de datos con el siguiente comando:
```
docker exec -it lamp-mysql8 /bin/bash
```

Conectamos con la base de datos con el siguiente comando:
```
mysql -u root -p
```

Y ejecutamos la siguiente sentencia SQL para modificar el campo `contrasenya` de la tabla `usuarios`:
```
USE SQLi;
ALTER TABLE usuarios MODIFY contrasenya VARCHAR(255) NOT NULL; 
```

Creamos el fichero `add_user.php` con el siguiente código:
```
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Conexión
$conn = new mysqli("database", "root", "MiContraseña", "SQLi"); 
// ← Usa "localhost" si no estás en Docker
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verificamos campos
    if (isset($_POST["username"]) && isset($_POST["password"])) {
        $username = $_POST["username"];
        $password = $_POST["password"];

        // Hasheamos contraseña
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Insertamos usuario
        $stmt = $conn->prepare("INSERT INTO usuarios (usuario, contrasenya) VALUES (?, ?)");
        if ($stmt === false) {
            die("Error en prepare: " . $conn->error);
        }

        $stmt->bind_param("ss", $username, $hashed_password);

        if ($stmt->execute()) {
            echo "✅ Usuario insertado correctamente.";
        } else {
            echo "❌ Error al insertar usuario: " . $stmt->error;
        }

        $stmt->close();
    } else {
        echo "⚠️ Por favor, rellena todos los campos.";
    }
}

$conn->close();
?>

<form method="post">
    <input type="text" name="username" placeholder="Usuario" required>
    <input type="password" name="password" placeholder="Contrasenya" required>
    <button type="submit">Crear Usuario</button>
</form>
```

Si accedemos a la URL http://localhost/add_user.php crearemos un nuevo usuario en la base de datos con la contraseña hasheada.


Podemos comprobarlo desde phpmyadmin en http://localhost:8080.


Creamos el fichero `login_weak1.php` con el código:
```
<?php
// creamos la conexión 
$conn = new mysqli("database", "root", "MyPassword", "SQLi");

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

        // NO PREVENIMOS SQL INJECTION, SOLO SE AGREGA PASSWORD_HASH
        $query = "SELECT contrasenya FROM usuarios WHERE usuario = '$username'";
        print("Consulta SQL: " . $query . "<br>");

        //realizamos la consulta y recogemos los resultados
        $result = $conn->query($query);
        if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                $hashed_password = $row["contrasenya"];
                // Verificación de contraseña hasheada
                if (password_verify($password, $hashed_password)) {
                        echo "Inicio de sesión exitoso";
                } else {
                        echo "Usuario o contraseña incorrectos";
                }
        } else {
                echo "Usuario no encontrado";
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

Obtenemos un login exitoso:

Si introducimos datos no correcto dará el mensaje de "Usuario o contraseña no correctos"

## Uso de consultas preparadas

Creamos el fichero `login_weak2.php` con el siguiente código:
```
<?php
// Conexión
$conn = new mysqli("database", "root", "MyPassword", "SQLi");
if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

// Procesamos petición POST o GET
if ($_SERVER["REQUEST_METHOD"] == "POST" || $_SERVER["REQUEST_METHOD"] == "GET") {
    $username = $_REQUEST["username"];
    $password = $_REQUEST["password"];

    print("Usuario: " . $username . "<br>");
    print("Contraseña: " . $password . "<br>");

    // Consulta segura con prepare + bind
    $query = "SELECT contrasenya FROM usuarios WHERE usuario = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    print("Consulta SQL (preparada): " . $query . "<br>");

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($hashed_password);
        $stmt->fetch();

        // Comprobamos si la contraseña ingresada coincide con el hash
        if (password_verify($password, $hashed_password)) {
            echo "✅ Inicio de sesión exitoso";
        } else {
            echo "❌ Usuario o contraseña incorrectos";
        }
    } else {
        echo "❌ Usuario no encontrado";
    }

    $stmt->close();
}
$conn->close();
?>

<!-- Formulario -->
<form method="post">
    <input type="text" name="username" placeholder="Usuario">
    <input type="password" name="password" placeholder="Contrasenya">
    <button type="submit">Iniciar Sesión</button>
</form>
```

Debemos editar la tabla usuarios para que almacene el campo `failed_attempts` y `last_attempt` para almacenar el número de intentos y la fecha de último intento de inicio de sesión:
```
USE SQLi;
ALTER TABLE usuarios ADD failed_attempts INT DEFAULT 0;
ALTER TABLE usuarios ADD last_attempt TIMESTAMP NULL DEFAULT NULL;
```

## Implementar autenticación multifactor (MFA)
