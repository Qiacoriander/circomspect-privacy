

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
   
   var mivar = in;
   
   a.in1 <== mivar;
   a.in2 <== mivar;
   
   out <== a.out;
    
}


component main = A();
