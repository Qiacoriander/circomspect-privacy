pragma circom 2.0.0;

template Potencia() {
    signal input in;
    signal output out;
    
    out <== in * in;
}

template Suma() {
    signal input a;
    signal input b;
    signal output out;
    
    out <== a + b;
}

template Modulo(p) {
    signal input in;
    signal output out;
    
    signal k <-- in \ p;  // División entera
    out <-- in % p;
    
    // Restricciones para asegurar la relación correcta
    in === out + p * k;
    
    // Restricción para asegurar que out < p usando IsZero
    component isZero = IsZero();
    isZero.in <== out - p + 1;
    isZero.out === 1;
}

// Necesitamos definir el template IsZero para la comparación
template IsZero() {
    signal input in;
    signal output out;
    signal inv <-- in != 0 ? 1/in : 0;
    out <== 1 - (in * inv);
    in * out === 0;
}

template CircuitoPrincipal(p) {
    // Entradas privadas
    signal input a;
    signal input b;
    
    // Salida pública
    signal output c;
    
    // Potencia de a
    component potA = Potencia();
    potA.in <== a;

    // Potencia de b
    component potB = Potencia();
    potB.in <== b;

    // Suma de las potencias
    component suma = Suma();
    suma.a <== potA.out;
    suma.b <== potB.out;

    // Módulo del resultado usando la plantilla Modulo
    component mod = Modulo(p);
    mod.in <== suma.out;
    
    // Salida
    c <== mod.out;

    // Restricciones para asegurar que las entradas son menores que p
    component aIsZero = IsZero();
    aIsZero.in <== a - p + 1;
    aIsZero.out === 1;
    
    component bIsZero = IsZero();
    bIsZero.in <== b - p + 1;
    bIsZero.out === 1;
}

// Definición del main
component main = CircuitoPrincipal(21888242871839275222246405745257275088548364400416034343698204186575808495617);