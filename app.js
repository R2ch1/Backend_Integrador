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
      [nombre, correo, hash, rol || 'cliente'],
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

const { authenticateToken, requireAdmin } = require('./middleware/auth');

const { requireOperatorOrAdmin } = require('./middleware/auth');

// REGISTRO OPERADOR (creado por admin)
app.post('/api/operadores', authenticateToken, requireAdmin, async (req, res) => {
  const { nombre, correo, contrasena } = req.body;

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
      [nombre, correo, hash, 'operador'],
      (error) => {
        if (error) {
          if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({
              mensaje: 'El correo ya está registrado',
            });
          }

          return res.status(500).json({
            mensaje: 'Error al crear operador',
          });
        }

        return res.status(201).json({
          mensaje: 'Operador creado correctamente',
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

// EDITAR USUARIO / CAMBIAR ROL (admin)
app.patch('/api/usuarios/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { nombre, correo, rol, contrasena } = req.body;

  if (!nombre && !correo && !rol && !contrasena) {
    return res.status(400).json({ mensaje: 'Nada para actualizar' });
  }

  try {
    const updates = [];
    const params = [];

    if (nombre) {
      updates.push('nombre = ?');
      params.push(nombre);
    }
    if (correo) {
      updates.push('correo = ?');
      params.push(correo);
    }
    if (rol) {
      updates.push('rol = ?');
      params.push(rol);
    }
    if (contrasena) {
      const hash = await bcrypt.hash(contrasena, 10);
      updates.push('contrasena = ?');
      params.push(hash);
    }

    params.push(id);

    const sql = `UPDATE usuarios SET ${updates.join(', ')} WHERE id_usuario = ?`;

    db.query(sql, params, (error, result) => {
      if (error) {
        if (error.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ mensaje: 'El correo ya está registrado' });
        }
        console.error('Error actualizando usuario:', error);
        return res.status(500).json({ mensaje: 'Error al actualizar usuario' });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ mensaje: 'Usuario no encontrado' });
      }

      return res.json({ mensaje: 'Usuario actualizado correctamente' });
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ mensaje: 'Error interno' });
  }
});

// LISTAR PLAZAS
app.get('/api/plazas', authenticateToken, requireOperatorOrAdmin, (req, res) => {
  db.query('SELECT id_plaza, numero_plaza, estado FROM plazas', (error, resultados) => {
    if (error) return res.status(500).json({ mensaje: 'Error al obtener plazas' });
    return res.json(resultados);
  });
});

// ACTUALIZAR ESTADO DE PLAZA
app.patch('/api/plazas/:id', authenticateToken, requireOperatorOrAdmin, (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;
  if (!estado) return res.status(400).json({ mensaje: 'Estado requerido' });

  db.query('UPDATE plazas SET estado = ? WHERE id_plaza = ?', [estado, id], (error, result) => {
    if (error) return res.status(500).json({ mensaje: 'Error al actualizar plaza' });
    if (result.affectedRows === 0) return res.status(404).json({ mensaje: 'Plaza no encontrada' });
    return res.json({ mensaje: 'Plaza actualizada' });
  });
});

// LISTAR ESTACIONAMIENTOS (entradas y salidas)
app.get('/api/estacionamientos', authenticateToken, requireOperatorOrAdmin, (req, res) => {
  // soporta filtros: plaza, estado, from, to, page, pageSize
  const { plaza, estado, from, to } = req.query;
  const page = parseInt(req.query.page) || 1;
  const pageSize = Math.min(parseInt(req.query.pageSize) || 20, 200);
  const where = [];
  const params = [];

  if (plaza) {
    where.push('p.numero_plaza = ?');
    params.push(plaza);
  }
  if (estado) {
    where.push('e.estado = ?');
    params.push(estado);
  }
  if (from) {
    where.push('e.hora_entrada >= ?');
    params.push(from);
  }
  if (to) {
    where.push('e.hora_entrada <= ?');
    params.push(to);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const countSql = `SELECT COUNT(*) as total FROM estacionamientos e
    LEFT JOIN plazas p ON e.id_plaza = p.id_plaza
    LEFT JOIN vehiculos v ON e.id_vehiculo = v.id_vehiculo
    ${whereSql}`;

  db.query(countSql, params, (cErr, cRows) => {
    if (cErr) {
      console.error('Error counting estacionamientos:', cErr);
      return res.status(500).json({ mensaje: 'Error al obtener registros' });
    }

    const total = cRows && cRows[0] ? cRows[0].total : 0;
    const offset = (page - 1) * pageSize;

    const sql = `SELECT e.id_estacionamiento, e.hora_entrada, e.hora_salida, e.estado, e.id_plaza, e.tiempo_total_minutos, e.monto_pagado,
      v.id_vehiculo, v.placa, v.modelo, v.color, v.id_usuario AS id_propietario,
      u.nombre AS propietario_nombre, u.correo AS propietario_correo,
      p.numero_plaza, p.estado AS plaza_estado,
      t.id_ticket, t.codigo_ticket
      FROM estacionamientos e
      LEFT JOIN vehiculos v ON e.id_vehiculo = v.id_vehiculo
      LEFT JOIN usuarios u ON v.id_usuario = u.id_usuario
      LEFT JOIN plazas p ON e.id_plaza = p.id_plaza
      LEFT JOIN tickets t ON t.id_estacionamiento = e.id_estacionamiento
      ${whereSql}
      ORDER BY e.hora_entrada DESC
      LIMIT ? OFFSET ?`;

    const finalParams = params.concat([pageSize, offset]);
    db.query(sql, finalParams, (error, rows) => {
      if (error) {
        console.error('Error listando estacionamientos:', error);
        return res.status(500).json({ mensaje: 'Error al obtener registros' });
      }
      return res.json({ total, page, pageSize, rows });
    });
  });
});

// CREAR ESTACIONAMIENTO (asignar plaza libre y crear vehiculo si hace falta)
app.post('/api/estacionamientos', authenticateToken, requireOperatorOrAdmin, async (req, res) => {
  const { placa, modelo, color, id_usuario } = req.body;

  if (!placa) return res.status(400).json({ mensaje: 'Placa requerida' });

  const q = (sql, params = []) => new Promise((resolve, reject) => {
    db.query(sql, params, (e, r) => (e ? reject(e) : resolve(r)));
  });

  db.beginTransaction(async (txErr) => {
    if (txErr) {
      console.error('Transaction begin error:', txErr);
      return res.status(500).json({ mensaje: 'Error de transacción' });
    }

    try {
      const vehRows = await q('SELECT id_vehiculo FROM vehiculos WHERE placa = ?', [placa]);
      let idVehiculo;

      if (vehRows && vehRows[0] && vehRows[0].id_vehiculo) {
        idVehiculo = vehRows[0].id_vehiculo;
      } else {
        let idUsuarioFinal = id_usuario;
        if (!idUsuarioFinal) {
          const visitanteRows = await q('SELECT id_usuario FROM usuarios WHERE correo = ?', ['visitante@local']);
          if (visitanteRows && visitanteRows[0] && visitanteRows[0].id_usuario) {
            idUsuarioFinal = visitanteRows[0].id_usuario;
          } else {
            const insertU = await q('INSERT INTO usuarios (nombre, correo, contrasena, rol) VALUES (?, ?, ?, ?)', ['Visitante', 'visitante@local', '$2b$10$visitante', 'cliente']);
            idUsuarioFinal = insertU.insertId || insertU;
          }
        }

        const insertV = await q('INSERT INTO vehiculos (placa, modelo, color, id_usuario) VALUES (?, ?, ?, ?)', [placa, modelo || null, color || null, idUsuarioFinal]);
        idVehiculo = insertV.insertId || insertV;
      }

      const plazaRows = await q("SELECT id_plaza FROM plazas WHERE estado = 'libre' LIMIT 1");
      if (!plazaRows || !plazaRows[0] || !plazaRows[0].id_plaza) {
        return db.rollback(() => res.status(409).json({ mensaje: 'No hay plazas libres' }));
      }

      const idPlaza = plazaRows[0].id_plaza;

      await q('UPDATE plazas SET estado = ? WHERE id_plaza = ?', ['ocupado', idPlaza]);

      const insertEst = await q('INSERT INTO estacionamientos (id_vehiculo, id_plaza, estado) VALUES (?, ?, ?)', [idVehiculo, idPlaza, 'activo']);

      db.commit((cErr) => {
        if (cErr) {
          console.error('Commit error:', cErr);
          return db.rollback(() => res.status(500).json({ mensaje: 'Error al crear estacionamiento' }));
        }

        return res.status(201).json({ mensaje: 'Estacionamiento creado', id_estacionamiento: insertEst.insertId || insertEst, id_plaza: idPlaza });
      });
    } catch (err) {
      console.error('Error crear estacionamiento:', err);
      return db.rollback(() => res.status(500).json({ mensaje: 'Error al crear estacionamiento' }));
    }
  });
});

// GENERAR TICKET para estacionamiento
app.post('/api/estacionamientos/:id/ticket', authenticateToken, requireOperatorOrAdmin, (req, res) => {
  const { id } = req.params;

  const codigo = `TKT-${Date.now()}-${Math.floor(Math.random() * 9000 + 1000)}`;
  db.query('INSERT INTO tickets (codigo_ticket, id_estacionamiento) VALUES (?, ?)', [codigo, id], (error, result) => {
    if (error) {
      if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ mensaje: 'Código duplicado' });
      console.error('Error crear ticket:', error);
      return res.status(500).json({ mensaje: 'Error al crear ticket' });
    }

    return res.status(201).json({ mensaje: 'Ticket generado', codigo_ticket: codigo, id_ticket: result.insertId });
  });
});

// OBTENER TICKET POR CODIGO
app.get('/api/tickets/:codigo', authenticateToken, requireOperatorOrAdmin, (req, res) => {
  const { codigo } = req.params;
  const sql = `SELECT t.id_ticket, t.codigo_ticket, e.id_estacionamiento, e.hora_entrada, e.hora_salida, e.estado, e.id_plaza,
    v.id_vehiculo, v.placa, v.modelo, v.color, u.id_usuario AS id_propietario, u.nombre AS propietario_nombre, u.correo AS propietario_correo
    FROM tickets t
    JOIN estacionamientos e ON t.id_estacionamiento = e.id_estacionamiento
    LEFT JOIN vehiculos v ON e.id_vehiculo = v.id_vehiculo
    LEFT JOIN usuarios u ON v.id_usuario = u.id_usuario
    WHERE t.codigo_ticket = ? LIMIT 1`;

  db.query(sql, [codigo], (error, rows) => {
    if (error) return res.status(500).json({ mensaje: 'Error al buscar ticket' });
    if (!rows.length) return res.status(404).json({ mensaje: 'Ticket no encontrado' });
    return res.json(rows[0]);
  });
});

// FINALIZAR ESTACIONAMIENTO
app.patch('/api/estacionamientos/:id/finalizar', authenticateToken, requireOperatorOrAdmin, (req, res) => {
  const { id } = req.params;

  db.query('SELECT * FROM estacionamientos WHERE id_estacionamiento = ?', [id], (err, rows) => {
    if (err) return res.status(500).json({ mensaje: 'Error al obtener estacionamiento' });
    if (!rows.length) return res.status(404).json({ mensaje: 'Estacionamiento no encontrado' });

    const estacion = rows[0];
    if (estacion.estado !== 'activo') return res.status(400).json({ mensaje: 'Estacionamiento no activo' });

    // calcular tiempo y monto (simplificado)
    db.query("SELECT precio_hora FROM tarifas WHERE activo = 1 LIMIT 1", (e, tarifas) => {
      if (e) return res.status(500).json({ mensaje: 'Error tarifas' });
      const precioHora = tarifas && tarifas[0] ? Number(tarifas[0].precio_hora) : 10;

      db.query('UPDATE estacionamientos SET hora_salida = NOW(), tiempo_total_minutos = TIMESTAMPDIFF(MINUTE, hora_entrada, NOW()), monto_pagado = CEIL(TIMESTAMPDIFF(MINUTE, hora_entrada, NOW())/60)*? , estado = ? WHERE id_estacionamiento = ?', [precioHora, 'finalizado', id], (updErr) => {
        if (updErr) return res.status(500).json({ mensaje: 'Error al finalizar estacionamiento' });

        // liberar plaza
        db.query('SELECT id_plaza FROM estacionamientos WHERE id_estacionamiento = ?', [id], (qErr, qRes) => {
          if (qErr) return res.status(500).json({ mensaje: 'Error al obtener plaza' });
          const idPlaza = qRes[0].id_plaza;
          db.query('UPDATE plazas SET estado = ? WHERE id_plaza = ?', ['libre', idPlaza], (pErr) => {
            if (pErr) return res.status(500).json({ mensaje: 'Error liberando plaza' });

            // crear pago (simplificado: pagado en efectivo)
            db.query('SELECT monto_pagado FROM estacionamientos WHERE id_estacionamiento = ?', [id], (mErr, mRes) => {
              if (mErr) return res.status(500).json({ mensaje: 'Error monto' });
              const monto = mRes[0].monto_pagado || 0;
              db.query('INSERT INTO pagos (id_estacionamiento, monto, metodo_pago, estado) VALUES (?, ?, ?, ?)', [id, monto, 'efectivo', 'pagado'], (payErr, payRes) => {
                if (payErr) return res.status(500).json({ mensaje: 'Error creando pago' });
                return res.json({ mensaje: 'Estacionamiento finalizado', monto_pagado: monto });
              });
            });
          });
        });
      });
    });
  });
});

// CREAR INCIDENCIA
app.post('/api/incidencias', authenticateToken, requireOperatorOrAdmin, (req, res) => {
  const { id_estacionamiento, descripcion, tipo } = req.body;
  if (!descripcion || !tipo) return res.status(400).json({ mensaje: 'Descripción y tipo requeridos' });

  db.query('INSERT INTO incidencias (id_estacionamiento, descripcion, tipo) VALUES (?, ?, ?)', [id_estacionamiento || null, descripcion, tipo], (err, result) => {
    if (err) return res.status(500).json({ mensaje: 'Error creando incidencia' });
    return res.status(201).json({ mensaje: 'Incidencia creada', id_incidencia: result.insertId });
  });
});

// LISTAR INCIDENCIAS
app.get('/api/incidencias', authenticateToken, requireOperatorOrAdmin, (req, res) => {
  // filtros simples: tipo, page, pageSize
  const { tipo } = req.query;
  const page = parseInt(req.query.page) || 1;
  const pageSize = Math.min(parseInt(req.query.pageSize) || 50, 500);
  const where = [];
  const params = [];

  if (tipo) {
    where.push('tipo = ?');
    params.push(tipo);
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const countSql = `SELECT COUNT(*) as total FROM incidencias ${whereSql}`;
  db.query(countSql, params, (cErr, cRows) => {
    if (cErr) return res.status(500).json({ mensaje: 'Error contando incidencias' });
    const total = cRows && cRows[0] ? cRows[0].total : 0;
    const offset = (page - 1) * pageSize;

    const sql = `SELECT i.id_incidencia, i.id_estacionamiento, i.descripcion, i.tipo, i.created_at, i.estado,
      e.id_plaza, v.placa
      FROM incidencias i
      LEFT JOIN estacionamientos e ON i.id_estacionamiento = e.id_estacionamiento
      LEFT JOIN vehiculos v ON e.id_vehiculo = v.id_vehiculo
      ${whereSql}
      ORDER BY i.created_at DESC
      LIMIT ? OFFSET ?`;

    const finalParams = params.concat([pageSize, offset]);
    db.query(sql, finalParams, (err, rows) => {
      if (err) return res.status(500).json({ mensaje: 'Error listando incidencias' });
      return res.json({ total, page, pageSize, rows });
    });
  });
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

// ACTUALIZAR VEHICULO (propietario o admin)
app.patch('/api/vehiculos/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { placa, modelo, color } = req.body;

  if (!placa && !modelo && !color) return res.status(400).json({ mensaje: 'Nada para actualizar' });

  db.query('SELECT id_usuario FROM vehiculos WHERE id_vehiculo = ?', [id], (err, rows) => {
    if (err) return res.status(500).json({ mensaje: 'Error al obtener vehículo' });
    if (!rows.length) return res.status(404).json({ mensaje: 'Vehículo no encontrado' });

    const ownerId = rows[0].id_usuario;
    // permitir si es admin o propietario
    if (req.usuario.rol !== 'admin' && Number(req.usuario.id) !== Number(ownerId)) {
      return res.status(403).json({ mensaje: 'Permisos insuficientes' });
    }

    const updates = [];
    const params = [];
    if (placa) {
      updates.push('placa = ?');
      params.push(placa);
    }
    if (modelo !== undefined) {
      updates.push('modelo = ?');
      params.push(modelo || null);
    }
    if (color !== undefined) {
      updates.push('color = ?');
      params.push(color || null);
    }

    params.push(id);

    const sql = `UPDATE vehiculos SET ${updates.join(', ')} WHERE id_vehiculo = ?`;
    db.query(sql, params, (uErr, result) => {
      if (uErr) {
        if (uErr.code === 'ER_DUP_ENTRY') return res.status(409).json({ mensaje: 'Placa ya registrada' });
        console.error('Error actualizando vehículo:', uErr);
        return res.status(500).json({ mensaje: 'Error al actualizar vehículo' });
      }
      return res.json({ mensaje: 'Vehículo actualizado' });
    });
  });
});

// ELIMINAR VEHICULO (propietario o admin)
app.delete('/api/vehiculos/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.query('SELECT id_usuario FROM vehiculos WHERE id_vehiculo = ?', [id], (err, rows) => {
    if (err) return res.status(500).json({ mensaje: 'Error al obtener vehículo' });
    if (!rows.length) return res.status(404).json({ mensaje: 'Vehículo no encontrado' });

    const ownerId = rows[0].id_usuario;
    if (req.usuario.rol !== 'admin' && Number(req.usuario.id) !== Number(ownerId)) {
      return res.status(403).json({ mensaje: 'Permisos insuficientes' });
    }

    db.query('DELETE FROM vehiculos WHERE id_vehiculo = ?', [id], (dErr, result) => {
      if (dErr) return res.status(500).json({ mensaje: 'Error al eliminar vehículo' });
      return res.json({ mensaje: 'Vehículo eliminado' });
    });
  });
});

    // DASHBOARD RESUMEN (plazas, vehiculos activos, ingresos del día)
    app.get('/api/dashboard', authenticateToken, requireOperatorOrAdmin, (req, res) => {
      // plazas totals
      db.query('SELECT COUNT(*) AS total, SUM(estado = "libre") AS libres, SUM(estado = "ocupado") AS ocupadas FROM plazas', (err, pRows) => {
        if (err) return res.status(500).json({ mensaje: 'Error al obtener plazas' });
        const plazas_total = pRows && pRows[0] ? pRows[0].total : 0;
        const plazas_libres = pRows && pRows[0] ? Number(pRows[0].libres || 0) : 0;
        const plazas_ocupadas = pRows && pRows[0] ? Number(pRows[0].ocupadas || 0) : 0;

        // vehiculos activos = estacionamientos activos
        db.query("SELECT COUNT(*) AS activos FROM estacionamientos WHERE estado = 'activo'", (e2, vRows) => {
          if (e2) return res.status(500).json({ mensaje: 'Error al obtener vehiculos activos' });
          const vehiculos_activos = vRows && vRows[0] ? vRows[0].activos : 0;

          // ingresos del día: sumar monto_pagado de estacionamientos finalizados con hora_salida hoy
          db.query("SELECT IFNULL(SUM(monto_pagado),0) AS ingresos FROM estacionamientos WHERE estado = 'finalizado' AND DATE(hora_salida) = CURDATE()", (e3, iRows) => {
            if (e3) return res.status(500).json({ mensaje: 'Error al obtener ingresos' });
            const ingresos_dia = iRows && iRows[0] ? Number(iRows[0].ingresos || 0) : 0;

            return res.json({ plazas_total, plazas_libres, plazas_ocupadas, vehiculos_activos, ingresos_dia });
          });
        });
      });
    });

module.exports = app;