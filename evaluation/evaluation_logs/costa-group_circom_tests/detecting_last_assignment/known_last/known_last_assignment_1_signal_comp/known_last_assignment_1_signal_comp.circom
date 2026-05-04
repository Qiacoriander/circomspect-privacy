
template C(){
    signal input in;
    signal output out;
    
    out <== in * in;
}


template B(){
    signal input in1;
    signal input in2;
    signal output out;

    out <== in1 * in2;
}


template A(){

   signal input in;
   
   signal output out;
   
   component a = B();
   component a1 = C();
   
   a1.in <== in;
   
   a.in1 <== a1.out;
   a.in2 <== a1.out;
   
   out <== a.out;
    
}


component main = A();
