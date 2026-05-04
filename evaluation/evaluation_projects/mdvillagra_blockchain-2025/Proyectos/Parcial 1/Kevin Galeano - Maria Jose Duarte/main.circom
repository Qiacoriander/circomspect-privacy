pragma circom 2.1.6;

include "utils.circom";

template TP1() {
  // Señales privadas de entrada
  signal input a;
  signal input b;

  // Señal pública de salida
  signal output c;
  
  // Señales internas
  signal sum;

  // Componentes internos 
  component sqrt_a = Square();
  component sqrt_b = Square();
  component modr = Mod(7);

  // Conexiones
  sqrt_a.in <== a;
  sqrt_b.in <== b;

  sum <== sqrt_a.out + sqrt_b.out;
  modr.in <== sum;

  // Salida
  c <== modr.out;
  log("\nEl resultado de ", a, "^2 + ", b, "^2 mod ", 7, " es ", c);
}

// Componente principal
component main = TP1();
