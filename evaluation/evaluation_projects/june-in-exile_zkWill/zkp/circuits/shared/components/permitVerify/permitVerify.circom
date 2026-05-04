pragma circom 2.2.2;

include "permitHash.circom";
include "typedDataHash.circom";
include "pubkeyRecover.circom";
include "../ecdsa/eth.circom";
include "../bus.circom";

/*
 * Verifies the permit2 signature contained in the will
 * 
 * The imeplementation corresponds to the contracts deployed
 * at Mainnet 0x000000000022d473030f116ddee9f6b43ac78ba3
 * (SignatureTransfer.sol, ./libraries/PermitHash.sol, etc.)
 */
template VerifyPermit(numPermission) {
    signal input {address} testator;   // 20 byte unsigned integer
    input PermitBatchTransferFrom(numPermission) permit;
    signal input {address} will;       // 20 byte unsigned integer
    input EcdsaSignature() signature;

    var n = 64, k = 4;
    // var chainId = 31337; // Anvil
    var chainId = 421614; // Arbitrum Sepolia

    // Hashes permit to get typed permit digest
    signal {bit} permitDigest[256] <== HashPermit(numPermission)(permit, will);
    signal {bit} typedPermitDigest[256] <== HashTypedData(chainId)(permitDigest);

    // Recovers signer from digest and signature
    signal pubkey[2][k] <== RecoverEcdsaPubkey(n, k)(typedPermitDigest, signature);
    signal pubkeyBits[512] <== FlattenPubkey(n, k)(pubkey);
    signal signer <== PubkeyToAddress()(pubkeyBits);

    // Check if signer is testator
    testator === signer;
}