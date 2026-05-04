pragma circom 2.0.0;

// Función independiente para comparación a < b (copiado de StackOverflow)
template LessThan(n) {
    signal input in[2];  // in[0] = a, in[1] = b
    signal output out;   // out = 1 si a < b, else 0

    signal diff <== in[1] - in[0] - 1;  // Si diff ≥ 0 → a < b

    // Implementación Num2Bits integrada
    signal bits[n];
    var lc = 0;
    for (var i = 0; i < n; i++) {
        bits[i] <-- (diff >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;  // Bit es 0 o 1
        lc += bits[i] * (1 << i);
    }
    lc === diff;  // Verifica la representación en bits

    out <== 1 - bits[n-1];  // bits[n-1] sería 1 si diff < 0
}

// Circuito principal
template Main() {
    // Entradas privadas
    signal input a;
    signal input b;
    
    // Entrada pública (número primo)
    signal input p;

    // Salida pública
    signal output c;

    // 1. Calcular a² y b²
    signal a_sq <== a * a;
    signal b_sq <== b * b;
    signal sum <== a_sq + b_sq;

    // 2. Cálculo del módulo seguro
    c <-- sum % p;  // Asignación temporal
    
    // Verificación: sum === c mod p
    signal k;
    k <-- (sum - c) / p;
    sum === k * p + c;

    // 3. Verificación c < p
    component lt = LessThan(252);
    lt.in[0] <== c;
    lt.in[1] <== p;
    lt.out === 1;  // Forzamos que c < p sea verdadero
}

component main = Main();
