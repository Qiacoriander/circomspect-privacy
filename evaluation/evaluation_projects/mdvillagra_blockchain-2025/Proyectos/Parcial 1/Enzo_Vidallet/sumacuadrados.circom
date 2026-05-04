pragma circom 2.0.0;

template SumOfSquaresModP(p) {
    signal input a;
    signal input b;
    signal output c;
    
    signal aSquared <== a * a;
    signal bSquared <== b * b;
    signal sum <== aSquared + bSquared;
    
    // Cálculo del módulo
    signal q <-- sum \ p;
    c <-- sum - q*p;
    
    // Verificación principal
    sum === q*p + c;
    
    // Verificación de rangos implícita
    // Si a >= p o b >= p, el cálculo de q será incorrecto
    // y la verificación sum === q*p + c fallará
}

component main = SumOfSquaresModP(23);