const request = require('supertest');
const app = require('../app');

describe('Vehiculos', () => {
  test('Registrar vehículo', async () => {
    const res = await request(app)
      .post('/api/vehiculos')
      .send({
        placa: `ABC${Date.now()}`,
        modelo: 'Toyota',
        color: 'Rojo',
        id_usuario: 1,
      });

    expect(res.statusCode).toBe(201);
  });
});