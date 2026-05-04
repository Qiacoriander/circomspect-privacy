bus MiBusPeque{
    signal a[2];
}


bus MiBus{
   signal b;
   MiBusPeque a[2];
}



template A(){
   MiBus input in;
   MiBus output out;
   
   if (in.b > 10){
       out.a <-- in.a;
   } else{
       out.a <-- in.a;
   }
   out.b <== 2;

}

component main = A();
