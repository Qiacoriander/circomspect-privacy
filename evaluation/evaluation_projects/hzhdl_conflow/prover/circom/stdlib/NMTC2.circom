pragma circom 2.1.6;
include "circomlib/circuits/mimc.circom"; //引入 mimc hash算法




/**
m为默克尔树子节点数
 */
template getmimcroot(){
    signal input x[4];
    signal output out;


    component mh[3];
    mh[0] = MultiMiMC7(2,91);
    mh[1] = MultiMiMC7(2,91);
    mh[2] = MultiMiMC7(2,91);


    mh[0].in[0] <== x[0];
    mh[0].in[1] <== x[1];
    mh[0].k <== 0;

    mh[1].in[0] <== mh[0].out;
    mh[1].in[1] <== x[2];
    mh[1].k <== 0;

    mh[2].in[0] <== mh[1].out;
    mh[2].in[1] <== x[3];
    mh[2].k <== 0;

    out <== mh[2].out;
}

template validationMTC(){

    signal input state[4];
    signal input newstate;
    signal output out[3];


    component mimcroots[2];
    mimcroots[0]=getmimcroot();
    mimcroots[1]=getmimcroot();

    mimcroots[0].x[0] <== state[0];
    mimcroots[0].x[1] <== state[1];
    mimcroots[0].x[2] <== state[2];
    mimcroots[0].x[3] <== state[3];


// 计算出旧的数据，若符合要求，更新的数据出来
    out[0] <== mimcroots[0].out;


//进行卷积并计算新的数据根

    component hash=MultiMiMC7(2,91);
    hash.in[0] <== state[1];
    hash.in[1] <== state[2];
    hash.k <== 0;

    mimcroots[1].x[0] <== state[0];
    mimcroots[1].x[1] <== hash.out;
    mimcroots[1].x[2] <== state[3];
    mimcroots[1].x[3] <== newstate;


    out[1] <== mimcroots[1].out;
    out[2] <== newstate;


}

//component main= validationMTC();





