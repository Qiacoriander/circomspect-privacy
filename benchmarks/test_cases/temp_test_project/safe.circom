template Safe() {
    signal input s;
    signal output o;
    o <== s * s;
}
component main = Safe();
