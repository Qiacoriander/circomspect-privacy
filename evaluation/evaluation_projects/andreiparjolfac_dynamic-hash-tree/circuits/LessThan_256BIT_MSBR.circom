pragma circom 2.1.6;

include "./Num2Bits.circom";
include "./Bits2Num.circom";
include "./LessThan.circom";
include "./isEqual.circom";

template LessThan_256BIT_MSBR(){
    signal input in[2];
    signal inter1[4];
    signal inter2[4];
    signal output out;
    component n2b = Num2Bits(256);
    component b2n[4] ;
    n2b.in <== in[0];
    for(var i=0;i<4;i++){
        b2n[i] = Bits2Num(64);
        for(var j=0;j<64;j++){
            b2n[i].in[j]<==n2b.out[j+(64*i)];
        }
        inter1[i]<==b2n[i].out;
    }

    component n2b_2 = Num2Bits(256);
    component b2n_2[4] ;
    n2b_2.in <== in[1];
    for(var i=0;i<4;i++){
        b2n_2[i] = Bits2Num(64);
        for(var j=0;j<64;j++){
            b2n_2[i].in[j]<==n2b_2.out[j+(64*i)];
        }
        inter2[i]<==b2n_2[i].out;
    }



    signal interBINcomp1[4];
    signal interBINcomp2[4];
    component interLT[4];
    component isEq[4];

    for(var i=0;i<4;i++){
        interLT[i] = LessThan();
        isEq[i] = isEqual();
        interLT[i].in[0]<==inter2[i];
        interLT[i].in[1]<==inter1[i];
        isEq[i].in[0]<==inter2[i];
        isEq[i].in[1]<==inter1[i];
        interBINcomp1[i]<== interLT[i].out;
        interBINcomp2[i]<== (1-interLT[i].out)-isEq[i].out;
    }

    signal num[2];
    component b2n_f[2];
    b2n_f[0]=Bits2Num(4);
    b2n_f[0].in[0]<== interBINcomp1[0];
    b2n_f[0].in[1]<== interBINcomp1[1];
    b2n_f[0].in[2]<== interBINcomp1[2];
    b2n_f[0].in[3]<== interBINcomp1[3];
    b2n_f[1]=Bits2Num(4);
    b2n_f[1].in[0]<== interBINcomp2[0];
    b2n_f[1].in[1]<== interBINcomp2[1];
    b2n_f[1].in[2]<== interBINcomp2[2];
    b2n_f[1].in[3]<== interBINcomp2[3];

    num[0]<== b2n_f[0].out;
    num[1]<== b2n_f[1].out;

    component LTF = LessThan();
    LTF.in[0]<==num[0];
    LTF.in[1]<==num[1];
    out<==LTF.out;

}
