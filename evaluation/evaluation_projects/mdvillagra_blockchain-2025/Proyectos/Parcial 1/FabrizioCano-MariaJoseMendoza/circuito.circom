pragma circom 2.2.2; 
//Template para calcular la suma de dos numeros
template Suma(){
    //declaracion de señales
    signal input a;
    signal input b;
    signal output outsuma; //las señales declaradas como ouput siempre son publicas

    outsuma<--a+b; //asignar el valor de c al resultado de la suma de a+b

    outsuma===a+b; //agregar una restriccion al sistema que debe cumplirse para el prover de manera a mostrar que la prueba de conomiento es correcta

}

template Potencia(){
    signal input base;
    signal output out;

    out<==base**2;
}


template Modulo() {
    signal input a; // Número a reducir
    signal input p; // Módulo
    signal output out;

    // Calcular el residuo
    signal q;
    q <-- a \ p; // Cociente (división entera)
    out <-- a % p; // Residuo

    // Restricciones para asegurar que a = q * p + out y out < p
    a === q * p + out;
    signal diff;
    diff <== p - out;
    diff * 1 === diff; // diff debe ser positivo
}

template Circuito() {
    signal input a; // Privada
    signal input b; // Privada
    signal input p; // Pública
    signal output c;//Publica
   
    // Calcular a^2
    component p1 = Potencia();
    p1.base <== a ; //asignar el valor de a a la señal base
    signal result1;
    result1 <== p1.out; //asignar el valor de la salida de la potencia a la señal result1 y comprobar la restriccion

    // Calcular b^2
    component p2 = Potencia();
    p2.base <== b ; //asignar el valor de b a la señal base
    signal result2;
    result2 <== p2.out; //asignar el valor de la salida de la potencia a la señal result2 y comprobar la restriccion

    // Calcular a^2 + b^2
    component s1 = Suma();
    s1.a <== result1 ; //asignar el valor de result1 a la señal a
    s1.b <== result2 ;//asignar el valor de result2 a la señal b
    signal suma;
    suma <== s1.outsuma ;

    // Calcular (a^2 + b^2) % p
    component mod = Modulo();
    mod.a <== suma ; //asignar el valor de suma a la señal a
    mod.p <== p ;// asignar el valor de p a la señal p
    c <== mod.out ; //asignar el valor de la salida de modulo a la señal c y comprobar la restriccion

   
    
}

component main {public [p]} = Circuito();