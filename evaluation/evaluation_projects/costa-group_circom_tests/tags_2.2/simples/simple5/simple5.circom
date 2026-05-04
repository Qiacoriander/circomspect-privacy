bus Bus1(){
    signal a[5];
    signal {value} b[2];
}

template B(){
    Bus1 input in;
    Bus1 output out <== in;
    
    in.b.value === 4;
    
}


template A(){

    signal input a[5];
    signal output b[5];
    
    signal {value} s;
    s.value = 4;
    s <== 5;
    
    signal {value} inter[3];
    inter.value = 4;
    inter[0] <== s;
    inter[1] <== s;
    inter[2] <== s;
    
    Bus1 aux;
    aux.a <== a;
    aux.b[0] <== inter[0];
    aux.b[1] <== inter[1];
    
    aux.b.value === 4;
    Bus1 output out <== B()(aux);
    
    b <== a;
}


component main = A();
