pragma circom 2.2.2;

template circuito(p)
{
    signal input a;
    signal input b;
    signal output c;
    signal acuadrado;
    signal bcuadrado;
    signal suma;
    signal cociente;

    acuadrado <== a * a;
    bcuadrado <== b * b;
    suma <== acuadrado + bcuadrado;
    cociente <-- suma \ p;
    c <-- suma % p;
    suma === cociente*p + c;
}

component main = circuito(17);