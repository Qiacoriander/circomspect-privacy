pragma circom 2.0.0;
include "circomlib/circuits/comparators.circom"; 

template Main() {
    signal input a;
    signal input b;
    signal output c;

    var p = 37;

    //Validacion: 0<=a<p y 0<=b<p
    component aCheck = LessThan(6);
    aCheck.in[0] <== a;
    aCheck.in[1] <== p;
    aCheck.out === 1;

    component bCheck = LessThan(6);
    bCheck.in[0] <== b;
    bCheck.in[1] <== p;
    bCheck.out === 1;

    //Calculo: c=(a² + b²)%p usando el teorema de la division
    signal a_sq <== a * a;
    signal b_sq <== b * b;
    signal sum <== a_sq + b_sq;

    //Descomposicion: sum=q*p+c (con 0<=c<p)
    signal q;
    c <-- sum % p;
    q <-- (sum - c) / p;

    //Restricciones para garantizar sum=q*p+c y 0<=c< p
    sum === q * p + c;
    component cCheck = LessThan(6);
    cCheck.in[0] <== c;
    cCheck.in[1] <== p;
    cCheck.out === 1;
}

component main = Main();