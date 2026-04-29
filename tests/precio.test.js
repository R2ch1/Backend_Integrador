const calcularPrecio = require('../servicios/calcularPrecio');

describe('Precio', () => {

  test('60 minutos = 2 Bs', () => {
    expect(calcularPrecio(60)).toBe(2);
  });

  test('45 minutos = 2 Bs', () => {
    expect(calcularPrecio(45)).toBe(2);
  });
  test('90 minutos = 3 Bs', () => {
    expect(calcularPrecio(90)).toBe(3);
  });

});