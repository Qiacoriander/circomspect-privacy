pragma circom 2.0.0;

include "../transformtwo.circom";

component main {public [grid, inColor, outColorBot, outColorTop]} = TransformTwo(8, 12);
