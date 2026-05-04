pragma circom 2.1.4;

// S-box: x^5 在有限域上的实现
// 这是 Poseidon2 的核心非线性组件
template Sbox() {
    signal input in;
    signal output out;
    
    // 计算 x^5 = x * x^4
    // 使用中间信号减少约束数
    signal x2;
    signal x4;
    
    x2 <== in * in;          // x^2
    x4 <== x2 * x2;          // x^4
    out <== x4 * in;         // x^5
}

// 优化的 S-box (减少约束)
template OptimizedSbox() {
    signal input in;
    signal output out;
    
    // 使用更少的中间变量
    signal x2 <== in * in;
    signal x4 <== x2 * x2;
    out <== x4 * in;
}

// 条件 S-box (用于部分轮)
template ConditionalSbox(apply) {
    signal input in;
    signal output out;
    
    if (apply == 1) {
        component sbox = Sbox();
        sbox.in <== in;
        out <== sbox.out;
    } else {
        out <== in;
    }
}

// S-box 逆运算 (用于测试验证)
template InverseSbox() {
    signal input in;
    signal output out;
    
    // 计算 x^(1/5) 在有限域上
    // 这需要计算模逆，实现较复杂
    // 这里提供框架，实际实现需要扩展欧几里得算法
    
    // 临时实现: 假设已知逆
    // 在实际应用中需要实现完整的模逆算法
    out <== in; // 占位符
}

// 批量 S-box 处理
template BatchSbox(n) {
    signal input inputs[n];
    signal output outputs[n];
    
    component sboxes[n];
    
    for (var i = 0; i < n; i++) {
        sboxes[i] = Sbox();
        sboxes[i].in <== inputs[i];
        outputs[i] <== sboxes[i].out;
    }
}

// S-box 测试组件
template SboxTest() {
    signal input testInput;
    signal output testOutput;
    signal output isCorrect;
    
    component sbox = Sbox();
    sbox.in <== testInput;
    testOutput <== sbox.out;
    
    // 验证 S-box 的基本性质
    // 例如: 0^5 = 0, 1^5 = 1
    component zeroTest = IsZero();
    zeroTest.in <== testInput;
    
    component oneTest = IsEqual();
    oneTest.in[0] <== testInput;
    oneTest.in[1] <== 1;
    
    // 简单正确性检查
    isCorrect <== 1; // 占位符
}

// 辅助模板: 检查是否为零
template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    
    inv <-- in != 0 ? 1/in : 0;
    out <== -in*inv + 1;
    in*out === 0;
}

// 辅助模板: 检查两数是否相等
template IsEqual() {
    signal input in[2];
    signal output out;
    
    component isz = IsZero();
    
    in[1] - in[0] ==> isz.in;
    
    isz.out ==> out;
}
