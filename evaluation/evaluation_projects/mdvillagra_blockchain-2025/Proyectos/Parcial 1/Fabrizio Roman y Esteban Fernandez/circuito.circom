pragma circom 2.0.0;

// Libreria para el componente LessThan
include "node_modules/circomlib/circuits/comparators.circom";

template Circuito(){
    signal input a;
    signal input b;
    signal input p;
    signal output c;

    signal a2;
    signal b2;
    signal suma;
    signal q;
    signal resto;

    // Se calcula (a^2 + b^2)
    a2 <== a * a;
    b2 <== b * b;
    suma <== a2 + b2;

    // Se calcula el modulo de 'suma' respecto a 'p'  
    resto <-- suma % p;

    // Se calcula el cociente de 'suma' respecto a 'p'
    q <-- suma \ p;

    // Se impone la restriccion: suma debe ser igual a (q * p + resto)
    suma === q * p + resto;

    // Se valida que resto < p  
    component lt = LessThan(252);
    lt.in[0] <== resto;
    lt.in[1] <== p;
    lt.out === 1;

    // La salida final c es igual a resto
    c <== resto;
}

component main {public [p]} = Circuito();