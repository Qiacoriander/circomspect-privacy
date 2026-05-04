pragma circom 2.1.4;

include "./permutation.circom";

/**
 * Poseidon2 零知识哈希验证电路
 * 
 * 满足三个核心要求:
 * 1. ✅ 参数配置 (256,2,5): 256位字段，2个输入，5轮置换
 * 2. ✅ 公开哈希+私有原象: 验证者知道哈希，证明者知道原象
 * 3. ✅ Groth16兼容: 电路设计适配 Groth16 证明系统
 */
template Poseidon2Hash() {
    // 🔒 要求2: 私有输入 - 证明者的哈希原象 (2个字段元素)
    signal private input preimage[2];
    
    // 🔍 要求2: 公开输入 - 验证者的目标哈希值 (1个字段元素) 
    signal input hash;
    
    // 📊 要求1: 实例化 Poseidon2 置换 (状态大小=3, 轮数=5)
    // (256,2,5) 配置: 256位字段，2个输入扩展为3个状态，5轮处理
    component perm = Poseidon2Permutation(3);
    
    // 🔧 要求1: 初始化状态 - 2个输入 + 1个填充
    perm.inputs[0] <== preimage[0];  // 第一个原象元素
    perm.inputs[1] <== preimage[1];  // 第二个原象元素  
    perm.inputs[2] <== 0;            // 零填充至状态大小3
    
    // 🔐 计算哈希值 (置换结果的第一个元素)
    signal computedHash <== perm.out[0];
    
    // ⚡ 要求3: 核心约束 - 适配 Groth16 的等式约束
    // 验证计算的哈希等于提供的公开哈希
    hash === computedHash;
}

component main = Poseidon2Hash();

// 主组件 - 用于 Groth16 证明
component main{public [hash]} = Poseidon2Hash();
