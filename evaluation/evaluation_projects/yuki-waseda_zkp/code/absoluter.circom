
template Num2abs() {
    signal input in;       // 入力値（正または負）
    signal output out;     // 絶対値
    
    // 符号判定（負の場合に1を返す）
    component isNegative = LessThan(252);
    isNegative.in[0] <== in;
    isNegative.in[1] <== 0;
    
    // 中間信号を定義
    signal negIn;
    signal posIn;
    signal selectedNeg;
    signal selectedPos;
    
    negIn <== -in;             // 反転した値
    posIn <== in;              // 正の値
    selectedNeg <== isNegative.out * negIn; // 負の場合の計算
    selectedPos <== (1 - isNegative.out) * posIn; // 正の場合の計算
    
    // 絶対値を計算
    out <== selectedNeg + selectedPos;