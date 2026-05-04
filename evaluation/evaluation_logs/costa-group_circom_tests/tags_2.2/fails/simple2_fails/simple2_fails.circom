bus Bus1(){
    signal a[5];
    signal {value} b[2];
}

template B(){
    Bus1 input in;
    Bus1 output out <== in;
    
    log(in.b.value);
    
}


template A(){

    signal input a[5];
    signal output b[5];
    
    signal {value} s;
    s.value = 77;
    s<== 4;
    
    signal {value} s1;
    s1.value = 4;
    s1 <== 2;
    
    Bus1 aux;
    aux.a <== a;
    aux.b[0] <== s1;
    aux.b[1] <== s;
    
    log(aux.b.value);
    
    Bus1 output out <== B()(aux);
    
    b <== a;
}


component main = A();
