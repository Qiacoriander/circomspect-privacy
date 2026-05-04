pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

// Верифікація шляху в дереві Меркла
template MerkleProof(levels) {
    // Публічний вхід - корінь дерева Меркла
    signal input root;
    
    // Приватні входи
    signal input leaf; // Значення елемента
    signal input pathElements[levels]; // Елементи шляху
    signal input pathIndices[levels]; // Індекси для вибору напрямку (ліво/право)
    
    // Проміжні змінні для побудови шляху
    component switchers[levels];
    component hashers[levels];
    
    // Поточний обчислений хеш - починаємо з листа
    signal currentHash[levels + 1];
    currentHash[0] <== leaf;
    
    // Обчислення хешів на кожному рівні дерева
    for (var i = 0; i < levels; i++) {
        // Використовуємо Switcher для вибору порядку хешування
        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== currentHash[i];
        switchers[i].R <== pathElements[i];
        
        // Хешування з правильним порядком
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;
        
        // Оновлюємо поточний хеш
        currentHash[i + 1] <== hashers[i].out;
    }
    
    // Перевіряємо, чи співпадає обчислений корінь з вхідним коренем
    root === currentHash[levels];
}

// Головний компонент - глибина буде задана при компиляції
component main {public [root]} = MerkleProof(16);