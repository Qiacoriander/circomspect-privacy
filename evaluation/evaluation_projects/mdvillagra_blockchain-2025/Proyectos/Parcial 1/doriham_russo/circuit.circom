pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

template Multiplier () {  

   signal input x;  
   signal input y;  
   signal output out;  

   out <== x * y;  
}

template CuadradoMod() {
    signal input a;    // Entrada privada
    signal input b;    // Entrada privada
    signal input P;    // Entrada publica
    signal output c;          

    
    component lt = LessThan(32);  // Ajustar según el tamaño de P
    component multiplyA = Multiplier();
    component multiplyB = Multiplier();
    multiplyA.x <== a;
    multiplyA.y <== a;
    multiplyB.x <== b;
    multiplyB.y <== b;

    var sum = multiplyA.out + multiplyB.out;
    

      // Calcular c = sum % P y k = floor(sum / P)
    signal k;

    c <-- sum % P;  // Asignación temporal
    k <-- (sum - c) / P;  // Asignación temporal

    sum === k * P + c;
    // Asegurar c < P
    lt.in[0] <== c;
    lt.in[1] <== P;
    lt.out === 1;
}

component main {public [P]} = CuadradoMod(); 