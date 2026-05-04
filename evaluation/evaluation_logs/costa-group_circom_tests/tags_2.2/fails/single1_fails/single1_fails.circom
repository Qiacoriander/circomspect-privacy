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
    s.value = 4;
    s <== 5;
    
    signal {value} inter[3];
    inter.value = 9;
    inter[0] <== s;
    inter[1] <== s;
    
    Bus1 aux;
    aux.a <== a;
    aux.b[0] <-- inter[0];
    aux.b[1] <== inter[1];
    
    log(aux.b.value);
    Bus1 output out <== B()(aux);
    
    b <== a;
}


component main = A();
