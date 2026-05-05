const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) {
    return res.status(401).json({ mensaje: 'Token requerido' });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ mensaje: 'Formato de token inválido' });
  }

  const token = parts[1];
  jwt.verify(token, process.env.JWT_SECRET || 'dev_secret', (err, payload) => {
    if (err) return res.status(401).json({ mensaje: 'Token inválido' });
    req.usuario = payload;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.usuario) return res.status(401).json({ mensaje: 'Token requerido' });
  if (req.usuario.rol !== 'admin') return res.status(403).json({ mensaje: 'Permisos insuficientes' });
  next();
}

module.exports = { authenticateToken, requireAdmin };
