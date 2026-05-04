include "../stdlib/NMTC2.circom";

template calMTCs(n){
    signal input state[n][4];
    signal input newstate[n];

    signal output out[n][3];

    component vaMTC[n];
    var i;
    for(i=0;i<n;i++){
        vaMTC[i]= validationMTC();

        vaMTC[i].state[0]<== state[i][0];
        vaMTC[i].state[1] <== state[i][1];
        vaMTC[i].state[2] <== state[i][2];
        vaMTC[i].state[3] <== state[i][3];
        vaMTC[i].newstate <== newstate[i];

        out[i][0] <== vaMTC[i].out[0];
        out[i][1] <== vaMTC[i].out[1];
        out[i][2] <== vaMTC[i].out[2];

    }
}

component main {public [newstate]}= calMTCs(14);
