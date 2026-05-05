const request = require('supertest');
const app = require('../app');

describe('Registro', () => {
  test('Registrar usuario', async () => {
    const res = await request(app)
      .post('/api/usuarios')
      .send({
        nombre: 'Test',
        correo: `test${Date.now()}@gmail.com`,
        contrasena: '123456',
        rol: 'cliente',
      });

    expect(res.statusCode).toBe(201);
  });
});