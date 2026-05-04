pragma circom 2.2.2;

include "../keccak256/keccak256.circom";

/*
 * The DOMAIN_SEPARATOR can be queried permit2 contract (fixed address: 0x000000000022d473030f116ddee9f6b43ac78ba3)
 *   - Mainnet: https://etherscan.io/address/0x000000000022d473030f116ddee9f6b43ac78ba3#readContract#F1
 *   - Arbitrum Sepolia: https://sepolia.arbiscan.io/address/0x000000000022d473030f116ddee9f6b43ac78ba3#readContract#F1
 *
 * @param chainId - Chain ID (Mainnet = 1, Arbitrum Sepolia = 421614, Anvil = 31337)
 */
function EIP712_DOMAIN_SEPARATOR(chainId) {
    var ANVIL[256] = [
        1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
        0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0,
        0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0,
        0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1,
        0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0,
        0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1,
        0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1,
        1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1,
        1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1,
        0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1,
        1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0,
        1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1,
        0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1,
        1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1,
        1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0
    ];
    // 0x4d553c58ae79a6c4ba64f0e690a5d1cd2deff8c6b91cf38300e0f2b76f9ee346

    var ARBITRUM_SEPOLIA[256] = [
        1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1,
        1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1,
        1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1,
        0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1,
        0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0,
        0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1,
        0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
        0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0,
        1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1,
        1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1,
        0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1,
        0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0,
        1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1,
        0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0,
        0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1
    ];
    // 0x97caedc57dcfc2ae625d68b894a8a814d7be09e29aa5321eebada2423410d9d0

    var MAINNET[256] = [
        0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0,
        0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1,
        1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1,
        1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0,
        0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1,
        0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1,
        0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1,
        1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0,
        1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1,
        1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1,
        1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
        1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
        0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
        0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0,
        1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0
    ];
    // 0x866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28

    if (chainId == 31337) {
        return ANVIL;
    }

    if (chainId == 421614) {
        return ARBITRUM_SEPOLIA;
    }

    return MAINNET;
}


/*
 * Solidity implementation: https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/EIP712.sol#L38
 *
 * @param chainId - Chain ID (Mainnet = 1, Arbitrum Sepolia = 421614)
 */
template HashTypedData(chainId) {
    signal input {bit} permitDigest[256];
    signal output {bit} typedPermitDigest[256];

    // abi.encodePacked("0x1901", DOMAIN_SEPARATOR, permitDigest)
    var BITS_PREFIX[2 * 8] = [1,0,0,1,1,0,0,0,1,0,0,0,0,0,0,0];
    var BITS_DOMAIN_SEPARATOR[32 * 8] = EIP712_DOMAIN_SEPARATOR(chainId);

    var totalBits = (2 + 32 + 32) * 8;
    signal {bit} encodedDigest[totalBits];

    var bitIdx = 0;
    for (var i = 0; i < 2 * 8; i++) {
        encodedDigest[bitIdx] <== BITS_PREFIX[i];
        bitIdx++;
    }
    for (var i = 0; i < 32 * 8; i++) {
        encodedDigest[bitIdx] <== BITS_DOMAIN_SEPARATOR[i];
        bitIdx++;
    }
    for (var i = 0; i < 32 * 8; i++) {
        encodedDigest[bitIdx] <== permitDigest[i];
        bitIdx++;
    }
    assert(bitIdx == totalBits);

    // keccak256(encodedValue)
    typedPermitDigest <== Keccak256(totalBits)(encodedDigest);
}
