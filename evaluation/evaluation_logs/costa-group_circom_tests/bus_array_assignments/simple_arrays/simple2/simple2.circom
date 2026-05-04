bus miBus(n){
  signal a;
  signal b;
}

bus otroBus(n){
  miBus(n) a[2];
}



template A(){
   otroBus(3) input in;
   miBus(3) input in1;
   
   miBus(3) output out[2] <== [in.a[0], in1];
   
   out[0].b === in.a[0].b;
   
   
}


component main = A();
