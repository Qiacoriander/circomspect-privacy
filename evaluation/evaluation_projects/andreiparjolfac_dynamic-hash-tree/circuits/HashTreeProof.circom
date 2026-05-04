pragma circom 2.1.6;

include "./HashTreeLevel.circom";
include "./Selector.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template HashTreeProof(depth){
    signal input sk;
    signal input siblingsPk[depth];
    signal input path[depth];
    signal input root;

    signal intermed[depth+1];

    component levelChecker[depth];
    component poseidon = Poseidon(1);
    poseidon.inputs[0] <== sk;
    poseidon.out ==> intermed[0];

    for(var i=0;i<depth;i++){
        levelChecker[i] = HashTreeLevel();
        levelChecker[i].in[0] <== intermed[i];
        levelChecker[i].in[1] <== siblingsPk[i];
        levelChecker[i].position <== path[i];
        levelChecker[i].out ==> intermed[i+1];
    }

    intermed[depth] === root;

}

component main {public [root]} = HashTreeProof(32);

/* INPUT = {
    "sk":"7",
    "siblingsPk":["8761383103374198182292249284037598775384145428470309206166618811601037048804","17335113179337928064279612591971005109473151093244424875205590399726005361102","4924824719679653695544344112002466960362482050425504983922056625160325123496"],
    "path":[ "0", "1", "1" ],
    "root":"12926426738483865258950692701584522114385179899773452321739143007058691921961"

} */