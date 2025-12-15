pragma circom 2.0.0;

// 示例：演示两种分析模式的区别

template Add() {
    signal input a;  // 在 main 中声明为 public
    signal input b;  // private
    signal output c;
    
    c <== a + b;
}

// main component 声明 a 为 public，b 为 private
component main {public [a]} = Add();

// 测试两种模式：
// 1. --mode all（默认）：
//    - 分析所有 template，不考虑 main 的 public 列表
//    - a 和 b 都被当作 private
//    - 结果：检测到 c 泄露了私有信息（Tainted）
//
// 2. --mode main：
//    - 从 main component 开始分析，考虑 public 列表
//    - a 被当作 public (Clean)，b 被当作 private (Tainted)
//    - 结果：检测到 c 泄露了私有信息（因为 b 是 private）
//
// 如果将 b 也加入 public 列表：component main {public [a, b]} = Add();
// 则在 main 模式下不会有警告（因为两个输入都是 public）
