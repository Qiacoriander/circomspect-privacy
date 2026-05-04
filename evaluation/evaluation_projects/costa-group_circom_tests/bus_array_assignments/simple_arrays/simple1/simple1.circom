bus miBus(n){
  signal a;
  signal b;
}



template A(){
   miBus(3) input in;
   
   miBus(3) output out[2] <== [in, in];
   
   out[1].b === in.b;
}


component main = A();
