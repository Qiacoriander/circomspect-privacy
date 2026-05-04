
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
       out.a[1].a[0] <-- in.a[0].a[0];
   } else{
       out.a[1].a[0] <-- in.a[0].a[0];

   }
   out.a[1].a <== [3,3];

}

component main = A();

