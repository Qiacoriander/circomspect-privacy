template LinearAdder() {
    // 定义输入信号
    signal input a;
    signal input b;
    signal output sum;
    signal temp;

    // 线性约束：a + b = sum
    temp <== a + b;
    sum <== temp * 2;
}

component main{public[a]} = LinearAdder();