pragma circom 2.1.8;
include "comparators.circom";


template AllUniqueElements(len) {
    signal input elements[len];

    component isEqual[len*(len-1)/2];

    var index = 0;
    for(var i = 0; i < len; i++) {
        for(var j = i+1; j < len; j++) {
            isEqual[index] = IsEqual();
            isEqual[index].in[0] <== elements[i];
            isEqual[index].in[1] <== elements[j];
            isEqual[index].out === 0;
            index++;
        }
    }
}


component main = AllUniqueElements(10);