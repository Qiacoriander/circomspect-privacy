pragma circom 2.0.0;

template ModSumSquare(p) {
    signal input a;  // Input signal
    signal input b;  // Input signal
    
    signal output c;  // Resultado Final (mod p)

    // Calcilo del modulo
    signal a_squared <== a * a;
    signal b_squared <== b * b;
    signal sum <== a_squared + b_squared;

    // Division theorem: sum = p * q + r
    signal q <== sum / p;  // Division entera
    signal r <== sum - q * p;  // calculo del resto

    c <== r;  // Resultado Final (mod p)
}

component main = ModSumSquare(17);  // Example with p = 17
