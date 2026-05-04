bus miBus(n){
  signal a;
  signal b;
}



template A(){
   miBus(3) input in[3];
   
   miBus(3) output out[3][3] <== [in, in, in];
   
   in[2].a === out[1][2].a;
   
   
}

component main = A();
