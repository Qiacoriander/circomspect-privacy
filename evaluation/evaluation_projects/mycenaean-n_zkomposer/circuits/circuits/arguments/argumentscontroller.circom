pragma circom 2.0.0;

include "./transformarguments.circom";
include "./stackarguments.circom";
include "./transformtwoarguments.circom";
include "./filterarguments.circom";
include "./rejectarguments.circom";

template ArgumentsController(NUM_TOTAL_ARGS, C, ARG_LEN) {
    signal input index;
    signal output arguments[NUM_TOTAL_ARGS][C][ARG_LEN];

    // Transform
    component ArgumentOne = ArgumentsTransformYellowRed(C, ARG_LEN);
    ArgumentOne.inputIndex <== index;
    arguments[1] <== ArgumentOne.out;

    component ArgumentTwo = ArgumentsTransformYellowBlue(C, ARG_LEN);
    ArgumentTwo.inputIndex <== index;
    arguments[2] <== ArgumentTwo.out;

    component ArgumentThree = ArgumentsTransformRedYellow(C, ARG_LEN);
    ArgumentThree.inputIndex <== index;
    arguments[3] <== ArgumentThree.out;

    component ArgumentFour = ArgumentsTransformRedBlue(C, ARG_LEN);
    ArgumentFour.inputIndex <== index;
    arguments[4] <== ArgumentFour.out;
    
    component ArgumentFive = ArgumentsTransformBlueYellow(C, ARG_LEN);
    ArgumentFive.inputIndex <== index;
    arguments[5] <== ArgumentFive.out;

    component ArgumentSix = ArgumentsTransformBlueRed(C, ARG_LEN);
    ArgumentSix.inputIndex <== index;
    arguments[6] <== ArgumentSix.out;

    // Stack
    component ArgumentNine = ArgumentsStackYellow(C, ARG_LEN);
    ArgumentNine.inputIndex <== index;
    arguments[7] <== ArgumentNine.out;

    component ArgumentSeven = ArgumentsStackRed(C, ARG_LEN);
    ArgumentSeven.inputIndex <== index;
    arguments[8] <== ArgumentSeven.out;

    component ArgumentEight = ArgumentsStackBlue(C, ARG_LEN);
    ArgumentEight.inputIndex <== index;
    arguments[9] <== ArgumentEight.out;

    // TransformTwo
    component ArgumentTen = ArgumentsTransformTwoYellowYellowRed(C, ARG_LEN);
    ArgumentTen.inputIndex <== index;
    arguments[10] <== ArgumentTen.out;

    component ArgumentEleven = ArgumentsTransformTwoYellowYellowBlue(C, ARG_LEN);
    ArgumentEleven.inputIndex <== index;
    arguments[11] <== ArgumentEleven.out;
    
    component ArgumentTwelve = ArgumentsTransformTwoYellowRedYellow(C, ARG_LEN);
    ArgumentTwelve.inputIndex <== index;
    arguments[12] <== ArgumentTwelve.out;

    component ArgumentThirteen = ArgumentsTransformTwoYellowRedBlue(C, ARG_LEN);
    ArgumentThirteen.inputIndex <== index;
    arguments[13] <== ArgumentThirteen.out;

    component ArgumentFourteen = ArgumentsTransformTwoYellowBlueYellow(C, ARG_LEN);
    ArgumentFourteen.inputIndex <== index;
    arguments[14] <== ArgumentFourteen.out;

    component ArgumentFiveteen = ArgumentsTransformTwoYellowBlueRed(C, ARG_LEN);
    ArgumentFiveteen.inputIndex <== index;
    arguments[15] <== ArgumentFiveteen.out;

    component ArgumentSixteen = ArgumentsTransformTwoRedRedYellow(C, ARG_LEN);
    ArgumentSixteen.inputIndex <== index;
    arguments[16] <== ArgumentSixteen.out;

    component ArgumentSeventeen = ArgumentsTransformTwoRedRedBlue(C, ARG_LEN);
    ArgumentSeventeen.inputIndex <== index;
    arguments[17] <== ArgumentSeventeen.out;
    
    component ArgumentEighteen = ArgumentsTransformTwoRedYellowRed(C, ARG_LEN);
    ArgumentEighteen.inputIndex <== index;
    arguments[18] <== ArgumentEighteen.out;

    component ArgumentNineteen = ArgumentsTransformTwoRedYellowBlue(C, ARG_LEN);
    ArgumentNineteen.inputIndex <== index;
    arguments[19] <== ArgumentNineteen.out;
    
    component ArgumentTwenty = ArgumentsTransformTwoRedBlueYellow(C, ARG_LEN);
    ArgumentTwenty.inputIndex <== index;
    arguments[20] <== ArgumentTwenty.out;

    component ArgumentTwentyOne = ArgumentsTransformTwoRedBlueRed(C, ARG_LEN);
    ArgumentTwentyOne.inputIndex <== index;
    arguments[21] <== ArgumentTwentyOne.out;
    
    component ArgumentTwentyTwo = ArgumentsTransformTwoBlueBlueYellow(C, ARG_LEN);
    ArgumentTwentyTwo.inputIndex <== index;
    arguments[22] <== ArgumentTwentyTwo.out;
    
    component ArgumentTwentyThree = ArgumentsTransformTwoBlueBlueRed(C, ARG_LEN);
    ArgumentTwentyThree.inputIndex <== index;
    arguments[23] <== ArgumentTwentyThree.out;
    
    component ArgumentTwentyFour = ArgumentsTransformTwoBlueYellowBlue(C, ARG_LEN);
    ArgumentTwentyFour.inputIndex <== index;
    arguments[24] <== ArgumentTwentyFour.out;

    component ArgumentTwentyFive = ArgumentsTransformTwoBlueYellowRed(C, ARG_LEN);
    ArgumentTwentyFive.inputIndex <== index;
    arguments[25] <== ArgumentTwentyFive.out;

    component ArgumentTwentySix = ArgumentsTransformTwoBlueRedYellow(C, ARG_LEN);
    ArgumentTwentySix.inputIndex <== index;
    arguments[26] <== ArgumentTwentySix.out;

    component ArgumentTwentySeven = ArgumentsTransformTwoBlueRedBlue(C, ARG_LEN);
    ArgumentTwentySeven.inputIndex <== index;
    arguments[27] <== ArgumentTwentySeven.out;
    
    // Reject
    component ArgumentTwentyEight = ArgumentsRejectYellow(C, ARG_LEN);
    ArgumentTwentyEight.inputIndex <== index;
    arguments[28] <== ArgumentTwentyEight.out;

    component ArgumentTwentyNine = ArgumentsRejectRed(C, ARG_LEN);
    ArgumentTwentyNine.inputIndex <== index;
    arguments[29] <== ArgumentTwentyNine.out;

    component ArgumentThirty = ArgumentsRejectBlue(C, ARG_LEN);
    ArgumentThirty.inputIndex <== index;
    arguments[30] <== ArgumentThirty.out;

    // Filter
    component ArgumentThirtyOne = ArgumentsFilterYellow(C, ARG_LEN);
    ArgumentThirtyOne.inputIndex <== index;
    arguments[31] <== ArgumentThirtyOne.out;

    component ArgumentThirtyTwo = ArgumentsFilterRed(C, ARG_LEN);
    ArgumentThirtyTwo.inputIndex <== index;
    arguments[32] <== ArgumentThirtyTwo.out;

    component ArgumentThirtyThree = ArgumentsFilterBlue(C, ARG_LEN);
    ArgumentThirtyThree.inputIndex <== index;
    arguments[33] <== ArgumentThirtyThree.out;
}
