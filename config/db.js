const mysql = require('mysql2');
require('dotenv').config();

console.log('[DB Config] Intentando conectar a MySQL...');
console.log('[DB Config] Host:', process.env.DB_HOST);
console.log('[DB Config] Puerto:', process.env.DB_PORT);
console.log('[DB Config] BD:', process.env.DB_NAME);
console.log('[DB Config] Usuario:', process.env.DB_USER);

const conexion = mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

conexion.connect((error) => {
    if (error) {
        console.error('[DB Config] Error al conectar MySQL:', error.message);
        console.error('[DB Config] Código de error:', error.code);
        console.error('[DB Config] Errno:', error.errno);
        
        // Reintentar conexión después de 5 segundos
        console.log('[DB Config] Reintentando conexión en 5 segundos...');
        setTimeout(() => {
            conexion.connect();
        }, 5000);
        return;
    }

    console.log(' MySQL conectado correctamente');
    console.log('[DB Config] Base de datos:', process.env.DB_NAME);
});

conexion.on('error', (err) => {
    console.error('[DB Config] Error de conexión MySQL:', err);
    
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('[DB Config] Reconectando...');
        conexion.connect();
    }
});

module.exports = conexion;