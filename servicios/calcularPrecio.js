function calcularPrecio(minutos) {
  const bloques = Math.ceil(minutos / 30);
  return bloques * 1;
}

module.exports = calcularPrecio;