bus miBus(n){
  signal a;
  signal b;
}


template B(){
   miBus(3) input in;
   miBus(3) output out[3] <== [in, in, in]; 
}


template A(){
   miBus(3) input in[3];
   
   miBus(3) output out[3][3] <== [in, B()(in[1]), in];
   
   in[1].a === out[1][1].a;
   
   
}


component main = A();
