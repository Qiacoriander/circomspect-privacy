pragma circom 2.0.0;

// Importar el componente LessThan de la librería estándar de Circom
include "node_modules/circomlib/circuits/comparators.circom";

template Mod() {
    signal input a;
    signal input b;
    signal input p; // p es una entrada pública (valor constante)
    signal output c;

    signal a2;
    signal b2;
    signal dividendo;
    signal cociente;

    // Calcular a^2 y b^2
    a2 <== a * a;
    b2 <== b * b;

    // Calcular el dividendo (a^2 + b^2)
    dividendo <== a2 + b2;

    // Calcular el cociente y el residuo (c)
    cociente <-- dividendo \ p;  // División entera
    c <-- dividendo % p;        // Módulo

    // Restricción para asegurar que dividendo = cociente * p + c
    dividendo === cociente * p + c;

   // Usar LessThan para verificar que c < p
    component lessThan = LessThan(252); // 252 es el número de bits para comparar
    lessThan.in[0] <== c;               // c es la señal que queremos comparar
    lessThan.in[1] <== p;               // p es el valor constante
    lessThan.out === 1;                 // Asegurar que c < p
}

component main {public [p]} = Mod();