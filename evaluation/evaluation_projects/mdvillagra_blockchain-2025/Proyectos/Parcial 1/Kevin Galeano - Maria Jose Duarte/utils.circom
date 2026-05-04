pragma circom 2.1.6; // Especifica la versión de Circom a usar

// Obtiene el bit más significativo (MSB) de un número de n bits
template GetMostSignificantBit(n) {
  signal input in; // Número de entrada del cual se extraerá el bit más significativo
  signal {binary} bits[n]; // Arreglo de bits que representa el número en binario
  signal output {binary} out; // Bit más significativo del número

  var lc1 = 0; // Variable auxiliar para la suma de términos

  var e2 = 1; // Factor multiplicador para reconstruir el número
  for (var i = 0; i < n; i++) {
    bits[i] <-- (in >> i) & 1; // Extraer cada bit de "in" de menor a mayor
    bits[i] * (bits[i] - 1) === 0; // Asegurar que cada bit sea 0 o 1
    lc1 += bits[i] * e2; // Reconstrucción del número en base 2
    e2 = e2 + e2; // Multiplicación por 2 en cada iteración
  }

  lc1 === in; // Verificación de que la conversión binaria sea correcta
  out <== bits[n-1]; // El bit más significativo se encuentra en la última posición
}

// Función para calcular el logaritmo base "b" de "a"
function logb(a, b) {
  if (a == 0) {
    return 0; // Si "a" es 0, el logaritmo es 0
  }
  var n = 1;
  var r = 0;
  while (n < a) {
    r++; // Incrementamos el contador de logaritmo
    n *= b; // Multiplicamos sucesivamente por "b"
  }
  return r; // Retorna el valor del logaritmo
}

// Circuito para verificar si un número es menor que una constante "ct"
template parallel LtConstant(ct) {
  signal input in; // Entrada del número a comparar
  var n = logb(ct, 2); // Calcula la cantidad de bits necesarios para representar "ct"

  component bit = GetMostSignificantBit(n + 1); // Obtiene el MSB del número con margen
  bit.in <== in + (1 << n) - ct; // Ajuste para verificar si in < ct
  1 - bit.out === 1; // Asegura que el MSB sea 0 si "in" es menor que "ct"
}

// Circuito para calcular el módulo de un número respecto a "q"
template parallel Mod(q) {
  signal input in; // Entrada del número
  signal output out; // Salida con el resultado de in % q

  out <== ModBound(q, 1 << 252)(in); // Aplica el módulo con un límite superior
}

// Circuito que calcula el módulo "q" asegurando que el resultado esté en el rango permitido
template ModBound(q, b) {
  signal input in; // Número de entrada
  signal quotient; // Cociente de la división entera
  signal output out; // Resultado de in % q

  quotient <-- in \ q; // División entera de in entre q
  out <-- in % q; // Residuo de la división

  LtConstant(q)(out); // Verifica que out < q

  var bound_quot = b \ q + 1; // Límite superior del cociente
  LtConstant(bound_quot)(quotient); // Verifica que quotient sea menor que el límite

  in === quotient * q + out; // Garantiza que la descomposición sea válida
}

// Circuito que calcula el cuadrado de un número
template Square() {
  signal input in; // Número de entrada
  signal output out; // Resultado del cuadrado de in
  out <== in * in; // Cálculo del cuadrado
}
