const request = require('supertest');
const app = require('../app');

describe('Auth', () => {
  test('Login correcto devuelve token', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        correo: 'richip@gmail.com',
        contrasena: 'Admin12345',
      });

    expect(res.statusCode).toBe(200);
    expect(res.body.token).toBeDefined();
  });

  test('Login incorrecto', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        correo: 'richip@hotmail.com',
        contrasena: 'Admin123456789',
      });

    expect(res.statusCode).not.toBe(200);
  });
});