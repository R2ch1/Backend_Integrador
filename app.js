const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./config/db');

const app = express();

app.use(cors());
app.use(express.json());

// Health
app.get('/', (req, res) => {
  res.json({
    ok: true,
    env: process.env.NODE_ENV || 'development',
  });
});

// LOGIN
app.post('/api/auth/login', (req, res) => {
  const { correo, contrasena } = req.body;

  if (!correo || !contrasena) {
    return res
      .status(400)
      .json({ mensaje: 'Email y contraseña son requeridos' });
  }

  const sql = 'SELECT * FROM usuarios WHERE correo = ?';

  db.query(sql, [correo], async (error, resultados) => {
    if (error) {
      console.error('Error DB login:', error);
      return res.status(500).json({ mensaje: 'Error al buscar usuario' });
    }

    if (!resultados.length) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }

    const usuario = resultados[0];

    try {
      const passwordValida = await bcrypt.compare(
        contrasena,
        usuario.contrasena
      );

      if (!passwordValida) {
        return res.status(401).json({
          mensaje: 'Contraseña incorrecta',
        });
      }

      const token = jwt.sign(
        {
          id: usuario.id_usuario,
          rol: usuario.rol,
        },
        process.env.JWT_SECRET || 'dev_secret',
        { expiresIn: '8h' }
      );

      return res.json({
        token,
        usuario: {
          id: usuario.id_usuario,
          nombre: usuario.nombre,
          correo: usuario.correo,
          rol: usuario.rol,
        },
      });
    } catch (err) {
      console.error(err);
      return res.status(500).json({
        mensaje: 'Error en autenticación',
      });
    }
  });
});

// REGISTRO
app.post('/api/usuarios', async (req, res) => {
  const { nombre, correo, contrasena, rol } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({
      mensaje: 'Nombre, correo y contraseña son requeridos',
    });
  }

  try {
    const hash = await bcrypt.hash(contrasena, 10);

    const sql =
      'INSERT INTO usuarios (nombre, correo, contrasena, rol) VALUES (?, ?, ?, ?)';

    db.query(
      sql,
      [nombre, correo, hash, rol || 'usuario'],
      (error) => {
        if (error) {
          if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({
              mensaje: 'El correo ya está registrado',
            });
          }

          return res.status(500).json({
            mensaje: 'Error al crear usuario',
          });
        }

        return res.status(201).json({
          mensaje: 'Usuario creado correctamente',
        });
      }
    );
  } catch (err) {
    return res.status(500).json({
      mensaje: 'Error interno',
    });
  }
});

// LISTAR USUARIOS
app.get('/api/usuarios', (req, res) => {
  db.query(
    'SELECT id_usuario, nombre, correo, rol FROM usuarios',
    (error, resultados) => {
      if (error) {
        return res.status(500).json({
          mensaje: 'Error al obtener usuarios',
        });
      }

      return res.json(resultados);
    }
  );
});

// CREAR VEHICULO
app.post('/api/vehiculos', (req, res) => {
  const { placa, modelo, color, id_usuario } = req.body;

  if (!placa || !id_usuario) {
    return res.status(400).json({
      mensaje: 'Placa e id_usuario son requeridos',
    });
  }

  const sql =
    'INSERT INTO vehiculos (placa, modelo, color, id_usuario) VALUES (?, ?, ?, ?)';

  db.query(
    sql,
    [placa, modelo || null, color || null, id_usuario],
    (error) => {
      if (error) {
        if (error.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({
            mensaje: 'Placa ya registrada',
          });
        }

        return res.status(500).json({
          mensaje: 'Error al crear vehiculo',
        });
      }

      return res.status(201).json({
        mensaje: 'Vehiculo creado',
      });
    }
  );
});

// LISTAR VEHICULOS
app.get('/api/vehiculos', (req, res) => {
  db.query(
    'SELECT id_vehiculo, placa, modelo, color, id_usuario FROM vehiculos',
    (error, resultados) => {
      if (error) {
        return res.status(500).json({
          mensaje: 'Error al obtener vehiculos',
        });
      }

      return res.json(resultados);
    }
  );
});

module.exports = app;