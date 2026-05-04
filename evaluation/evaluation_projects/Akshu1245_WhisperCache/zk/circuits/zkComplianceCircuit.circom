pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * ZK Compliance Circuit
 * 
 * Proves compliance with data protection regulations without revealing:
 * - The actual data being protected
 * - Specific access patterns
 * - Individual user identities
 * 
 * This circuit verifies:
 * 1. Data retention policies are followed
 * 2. Access was properly authorized
 * 3. Encryption standards are met
 * 4. Audit logs exist for all operations
 * 
 * Inputs (Private):
 *   - dataHash: Hash of protected data
 *   - encryptionKeyHash: Hash proving encryption was used
 *   - accessorSecret: Secret of the accessing entity
 *   - auditLogHash: Hash of the audit log entry
 *   - retentionDays: Number of days data has been stored
 * 
 * Inputs (Public):
 *   - complianceStandard: Encoded compliance standard (1=GDPR, 2=HIPAA, 3=CCPA)
 *   - maxRetentionDays: Maximum allowed retention period
 *   - accessPolicyHash: Hash of the access control policy
 *   - auditCommitment: Public commitment to audit trail
 * 
 * Outputs:
 *   - isCompliant: 1 if all compliance checks pass
 *   - complianceScore: Encoded compliance score (0-100)
 *   - complianceProofHash: Verifiable proof of compliance
 */

template ZKComplianceCircuit() {
    // Private inputs
    signal input dataHash;
    signal input encryptionKeyHash;
    signal input accessorSecret;
    signal input auditLogHash;
    signal input retentionDays;
    
    // Public inputs
    signal input complianceStandard;
    signal input maxRetentionDays;
    signal input accessPolicyHash;
    signal input auditCommitment;
    
    // Outputs
    signal output isCompliant;
    signal output complianceScore;
    signal output complianceProofHash;
    
    // ========== Check 1: Retention Policy ==========
    // Data must not exceed maximum retention period
    component retentionCheck = LessEqThan(32);
    retentionCheck.in[0] <== retentionDays;
    retentionCheck.in[1] <== maxRetentionDays;
    
    signal retentionCompliant;
    retentionCompliant <== retentionCheck.out;
    
    // ========== Check 2: Encryption Verification ==========
    // Prove that data is encrypted (encryptionKeyHash != 0)
    signal encryptionActive;
    signal encKeyInv;
    encKeyInv <-- encryptionKeyHash != 0 ? 1/encryptionKeyHash : 0;
    encryptionActive <== encryptionKeyHash * encKeyInv;
    
    // ========== Check 3: Access Authorization ==========
    // Verify accessor is authorized by checking against policy
    component accessHasher = Poseidon(2);
    accessHasher.inputs[0] <== accessorSecret;
    accessHasher.inputs[1] <== dataHash;
    
    signal accessCheck;
    accessCheck <== accessHasher.out - accessPolicyHash;
    
    signal accessInv;
    accessInv <-- accessCheck != 0 ? 1/accessCheck : 0;
    signal accessAuthorized;
    accessAuthorized <== 1 - accessCheck * accessInv;
    accessCheck * accessAuthorized === 0;
    
    // ========== Check 4: Audit Trail Verification ==========
    // Verify audit log commitment is valid
    component auditHasher = Poseidon(3);
    auditHasher.inputs[0] <== auditLogHash;
    auditHasher.inputs[1] <== dataHash;
    auditHasher.inputs[2] <== accessorSecret;
    
    signal auditCheck;
    auditCheck <== auditHasher.out - auditCommitment;
    
    signal auditInv;
    auditInv <-- auditCheck != 0 ? 1/auditCheck : 0;
    signal auditValid;
    auditValid <== 1 - auditCheck * auditInv;
    auditCheck * auditValid === 0;
    
    // ========== Calculate Compliance Score ==========
    // Each check is worth 25 points
    signal score1;
    signal score2;
    signal score3;
    
    score1 <== retentionCompliant * 25;
    score2 <== score1 + encryptionActive * 25;
    score3 <== score2 + accessAuthorized * 25;
    complianceScore <== score3 + auditValid * 25;
    
    // ========== Overall Compliance ==========
    // Must pass all checks
    signal partial1;
    signal partial2;
    partial1 <== retentionCompliant * encryptionActive;
    partial2 <== partial1 * accessAuthorized;
    isCompliant <== partial2 * auditValid;
    
    // ========== Generate Compliance Proof Hash ==========
    component proofHasher = Poseidon(4);
    proofHasher.inputs[0] <== complianceStandard;
    proofHasher.inputs[1] <== complianceScore;
    proofHasher.inputs[2] <== dataHash;
    proofHasher.inputs[3] <== auditCommitment;
    
    complianceProofHash <== proofHasher.out;
}

component main {public [complianceStandard, maxRetentionDays, accessPolicyHash, auditCommitment]} = ZKComplianceCircuit();
