pragma circom 2.2.2;

template VerifySumOfSquaresModP() {
    signal input a; // Privada por defecto
    signal input b; // Privada por defecto
    signal input p; // Pública (declarada en main)
    signal input c; // Pública (declarada en main)
    signal input q; // PRIVADA - Debe ser calculada y proporcionada por el prover

    signal a_squared;
    signal b_squared;
    signal sum_squares;

    a_squared <== a * a;
    b_squared <== b * b;
    sum_squares <== a_squared + b_squared;

    // Ahora q tiene un valor (como input)
    // Esta restricción VERIFICA que el q, p, c son consistentes con a y b
    q * p + c === sum_squares;
}

// q no aparece, por lo que queda privada
component main {public [p, c]} = VerifySumOfSquaresModP();