pragma circom  2.2.2;
include "../node_modules/circomlib/circuits/comparators.circom";
template Modulo(n) {
    signal input dividend;
    signal input divisor;
    signal output remainder;

    // Verificar que el divisor no sea cero
    component isZero = IsZero();
    isZero.in <== divisor;
    isZero.out === 0;

    // Calcular cociente y resto
    signal quotient;
    quotient <-- dividend \ divisor;
    remainder <-- dividend % divisor;

    // Verificar: dividendo = cociente * divisor + resto
    dividend === quotient * divisor + remainder;

    // Verificar que el resto sea menor que el divisor
    component lt = LessThan(n);
    lt.in[0] <== remainder;
    lt.in[1] <== divisor;
    lt.out === 1;
}

template MainCircuit() {
    // Entradas priv
    signal input a;
    signal input b;
    // Entrada pub
    signal input p;
    // Salida pub
    signal output c;

    // Verificar que p no sea cero
    component isZero = IsZero();
    isZero.in <== p;
    isZero.out === 0;
    
    // Calcular a² y b²
    signal aSquared;
    aSquared <== a * a;

    signal bSquared;
    bSquared <== b * b;

    // Suma de cuadrados
    signal sum;
    sum <== aSquared + bSquared;

    
    component mod = Modulo(252);
    mod.dividend <== sum;
    mod.divisor <== p;
    c <== mod.remainder;
}

component main {public [p]} = MainCircuit();