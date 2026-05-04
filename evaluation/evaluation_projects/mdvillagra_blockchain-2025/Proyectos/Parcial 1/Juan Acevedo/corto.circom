pragma circom 2.0.0;

template z() {
    var p = 13;
    signal input a;
    signal input b;
    signal output r;

    // Restricciones cuadraticas
    signal a2 <== a * a;
    signal b2 <== b * b;

    signal suma <== a2 + b2; 
    r <-- suma % p; // Asigna la reduccion pero por si solo es peligroso

    // Para eso agregamos una restriccion
    signal q <-- (suma - r) / p; // Calculamos el cociente
    suma === q * p + r; // Restriccion con relacion a la formula de reduccion
}

component main = z();
