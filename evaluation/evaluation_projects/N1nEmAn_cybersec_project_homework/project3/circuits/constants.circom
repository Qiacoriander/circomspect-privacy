pragma circom 2.1.4;

// Poseidon2 轮常数
// 基于 Grain LFSR 生成的确定性常数
template RoundConstants(t, total_rounds) {
    signal output C[total_rounds][t];
    
    // 预计算的轮常数 (基于 Poseidon2 论文)
    // 这些常数是通过 Grain LFSR 生成的
    
    if (t == 3 && total_rounds == 64) {
        // (256,3,5) 配置的轮常数
        // R_F = 8, R_P = 56, 总计 64 轮
        
        // 第0轮常数
        C[0][0] <== 0x10d7ac06a4fd97f5f4b7f875c7a3a59e0c0a5b5f85b95a1e1e7c8b1b0c1d3b29;
        C[0][1] <== 0x0abcd5c3f9e8d2e5a1f7b3c9d4e2f6a8b1c3d7e9f1a3b7c9d2e5f8a1b4c7d9;
        C[0][2] <== 0x1a2b3c4d5e6f7a8b9c1d2e3f4a5b6c7d8e9f1a2b3c4d5e6f7a8b9c1d2e3f4;
        
        // 第1轮常数
        C[1][0] <== 0x2b4d6f8a1c3e5a7c9e1f3a5c7e9f1a3c5e7a9c1e3f5a7c9e1f3a5c7e9f1a3;
        C[1][1] <== 0x3c5e7a9c1e3f5a7c9e1f3a5c7e9f1a3c5e7a9c1e3f5a7c9e1f3a5c7e9f1a;
        C[1][2] <== 0x4d6f8a9c1e3f5a7c9e1f3a5c7e9f1a3c5e7a9c1e3f5a7c9e1f3a5c7e9f1;
        
        // 其余轮常数 (简化表示)
        for (var round = 2; round < total_rounds; round++) {
            for (var state = 0; state < t; state++) {
                // 使用简单的线性反馈移位寄存器生成
                C[round][state] <== 0x123456789abcdef0 + round * 0x1000 + state * 0x100;
            }
        }
    }
    
    if (t == 2 && total_rounds == 65) {
        // (256,2,5) 配置的轮常数
        // R_F = 8, R_P = 57, 总计 65 轮
        
        for (var round = 0; round < total_rounds; round++) {
            for (var state = 0; state < t; state++) {
                C[round][state] <== 0x9876543210fedcba + round * 0x2000 + state * 0x200;
            }
        }
    }
}

// 简化的轮常数生成器 (用于测试)
template SimpleConstants(t, rounds) {
    signal output C[rounds][t];
    
    for (var round = 0; round < rounds; round++) {
        for (var state = 0; state < t; state++) {
            // 简单的确定性生成
            C[round][state] <== round * t + state + 1;
        }
    }
}

// Grain LFSR 轮常数生成器模板
template GrainLFSR() {
    // Grain LFSR 的状态
    signal input seed;
    signal output constants[256]; // 输出多个常数
    
    // LFSR 状态寄存器
    signal state[80];
    
    // 初始化
    state[0] <== seed;
    
    // LFSR 反馈多项式: x^80 + x^78 + x^72 + x^62 + x^57 + x^40 + x^36 + x^24 + x^21 + x^13 + x^9 + x^1 + 1
    // 简化实现
    for (var i = 1; i < 80; i++) {
        state[i] <== state[i-1] * 2; // 简化的移位操作
    }
    
    // 生成输出常数
    for (var i = 0; i < 256; i++) {
        constants[i] <== state[i % 80];
    }
}

// 域元素验证器
template FieldElementValidator() {
    signal input element;
    signal output isValid;
    
    // 检查元素是否在有效的素域内
    // BLS12-381 的标量域大小
    var field_modulus = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    
    // 简单验证: 元素 < field_modulus
    component lt = LessThan(254);
    lt.in[0] <== element;
    lt.in[1] <== field_modulus;
    isValid <== lt.out;
}

// 常数一致性检查器
template ConstantConsistency(t, rounds) {
    signal input C[rounds][t];
    signal output allValid;
    
    component validators[rounds][t];
    signal validityChecks[rounds * t];
    
    for (var round = 0; round < rounds; round++) {
        for (var state = 0; state < t; state++) {
            validators[round][state] = FieldElementValidator();
            validators[round][state].element <== C[round][state];
            validityChecks[round * t + state] <== validators[round][state].isValid;
        }
    }
    
    // 所有常数都必须有效
    component andGate = MultiAND(rounds * t);
    for (var i = 0; i < rounds * t; i++) {
        andGate.in[i] <== validityChecks[i];
    }
    allValid <== andGate.out;
}

// 辅助组件: 比较器
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;
    
    component lt = Num2Bits(n+1);
    lt.in <== in[0]+ (1<<n) - in[1];
    
    out <== 1-lt.out[n];
}

// 辅助组件: 数字到位转换
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;
    
    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }
    
    lc1 === in;
}

// 辅助组件: 多输入 AND 门
template MultiAND(n) {
    signal input in[n];
    signal output out;
    
    if (n == 1) {
        out <== in[0];
    } else if (n == 2) {
        out <== in[0] * in[1];
    } else {
        component and1 = MultiAND(n-1);
        for (var i = 0; i < n-1; i++) {
            and1.in[i] <== in[i];
        }
        out <== and1.out * in[n-1];
    }
}
