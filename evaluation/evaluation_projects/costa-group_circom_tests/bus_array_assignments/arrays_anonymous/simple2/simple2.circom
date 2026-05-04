bus miBus(n){
  signal a;
  signal b;
}

bus otroBus(n){
  miBus(n) a[3];
}


template B(){
   miBus(3) input in;
   miBus(3) output out[3] <== [in, in, in]; 
}


template A(){
   otroBus(3) input in;
   miBus(3) input in1;
   
   miBus(3) output out[2][3] <== [in.a, B()(in1)];
   
   out[0][1].a === in.a[1].a;
   out[1][1].a === in1.a;
   
   
}


component main = A();
