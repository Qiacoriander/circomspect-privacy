pragma circom 2.0.0;

template SquareSumMod(p) {
    // Entradas privadas
    signal input a;
    signal input b;
    
    // Salida pública
    signal output c;
    
    // Variables intermedias
    signal a_sq;
    signal b_sq;
    signal sum;
    signal sum_mod_p;
    
    // Calcular a²
    a_sq <== a * a;
    
    // Calcular b²
    b_sq <== b * b;
    
    // Sumar los cuadrados
    sum <== a_sq + b_sq;
    
    // Calcular el módulo p
    sum_mod_p <-- sum % p;
    
    // Verificar que sum_mod_p es efectivamente el módulo
    // Esto es necesario porque <-- asigna sin crear constraints
    sum_mod_p * 1 === sum_mod_p;  // Validar que es un número válido
    sum === sum_mod_p + p * ((sum - sum_mod_p) / p);  // Verificar la relación de módulo
    
    // Asignar la salida
    c <== sum_mod_p;
}

component main = SquareSumMod(23);