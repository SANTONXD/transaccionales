const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();

// Middleware para parsear datos del formulario (application/x-www-form-urlencoded)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuración de sesión
app.use(session({
  secret: '1234', // cambia esta clave por una segura
  resave: false,
  saveUninitialized: true,
}));

// Conexión a la base de datos MySQL
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '', // tu contraseña de MySQL
  database: 'sistemas'
});

const promisePool = pool.promise();

// Ruta para servir archivos estáticos (HTML, CSS, etc.)
app.use(express.static('public')); // asegúrate de colocar tus archivos HTML (index.html y registro.html) en la carpeta "public"

// RUTA DE REGISTRO
app.post('/register', async (req, res) => {
    const { name, user, email, rol, password } = req.body;
    try {
      // Verificar si el correo ya existe
      const [existing] = await promisePool.query(
        'SELECT * FROM Usuarios WHERE email = ?',
        [email]
      );
      if (existing.length > 0) {
        return res.status(400).send('El correo ya se encuentra registrado');
      }
      // Hashear la contraseña
      const hashedPassword = await bcrypt.hash(password, 10);
      // Insertar el nuevo usuario en la tabla Usuarios
      await promisePool.query(
        'INSERT INTO Usuarios (nombre, apellido, email, password, rol) VALUES (?, ?, ?, ?, ?)',
        [name, user, email, hashedPassword, rol.toLowerCase()] // se asume que en la DB se almacena en minúsculas
      );
      // Redirigir al login tras el registro exitoso
      res.redirect('/index.html');
    } catch (error) {
      console.error(error);
      res.status(500).send('Error en el registro');
    }
  });

// RUTA DE LOGIN
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
      // Buscar usuario por email
      const [rows] = await promisePool.query(
        'SELECT * FROM Usuarios WHERE email = ?',
        [email]
      );
      if (rows.length === 0) {
        return res.status(401).send('Usuario no encontrado');
      }
      const userData = rows[0];
      // Comparar la contraseña ingresada con el hash almacenado
      const validPassword = await bcrypt.compare(password, userData.password);
      if (!validPassword) {
        return res.status(401).send('Contraseña incorrecta');
      }
      // Guardar información en la sesión
      req.session.userId = userData.id_usuario;
      req.session.rol = userData.rol;
      
      // Redirigir al dashboard, pasando el rol como parámetro en la URL
      res.redirect(`/principal.html?rol=${userData.rol}`);
    } catch (error) {
      console.error(error);
      res.status(500).send('Error en el login');
    }
  });

// Ruta de ejemplo protegida que muestra el rol del usuario
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).send('Debes iniciar sesión');
  }
  res.send(`Dashboard: Accediste como ${req.session.rol}`);
});

// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
});