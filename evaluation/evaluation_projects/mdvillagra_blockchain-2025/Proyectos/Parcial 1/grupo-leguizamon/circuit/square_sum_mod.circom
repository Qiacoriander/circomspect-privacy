pragma circom 2.0.0;

template SquareSumMod(p) {
    signal input a;
    signal input b;
    signal output c;

    signal a_squared;
    signal b_squared;
    signal sum;
    signal q;
    signal prod;

    // Calcular a² y b²
    a_squared <== a * a;
    b_squared <== b * b;

    // Calcular la suma de los cuadrados
    sum <== a_squared + b_squared;

    // Definir q como el cociente entero de sum / p
    q <== sum / p;

    // Calcular el producto de q y p
    prod <== q * p;

    // Calcular c como el residuo de sum / p
    c <== sum - prod;

    // Restricción para asegurar que sum = q * p + c
    sum === prod + c;
}

component main = SquareSumMod(97);

