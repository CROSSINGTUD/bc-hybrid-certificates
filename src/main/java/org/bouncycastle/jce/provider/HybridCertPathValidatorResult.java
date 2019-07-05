package org.bouncycastle.jce.provider;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.security.PublicKey;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;

public class HybridCertPathValidatorResult extends PKIXCertPathValidatorResult {

    private AsymmetricKeyParameter hybridKey;
    private boolean hybridChainValidated;

    public HybridCertPathValidatorResult(TrustAnchor trustAnchor, PolicyNode policyTree, PublicKey subjectPublicKey, AsymmetricKeyParameter hybridKey, boolean hybridChainValidated) {
        super(trustAnchor, policyTree, subjectPublicKey);
        this.hybridKey = hybridKey;
        this.hybridChainValidated = hybridChainValidated;
    }

    public HybridCertPathValidatorResult(PKIXCertPathValidatorResult result, AsymmetricKeyParameter hybridKey, boolean hybridChainValidated) {
        this(result.getTrustAnchor(), result.getPolicyTree(), result.getPublicKey(), hybridKey, hybridChainValidated);
    }

    /**
     * Returns the secondary key from the last certificate of the chain. Can be null (even if the hybrid validation was successful) if the last certificate is a partly hybrid certificate
     * and does not contain a secondary key.
     *
     * @return The secondary public key from the end entity certificate
     */
    public AsymmetricKeyParameter getHybridKey() {
        return hybridKey;
    }

    /**
     *
     * @return whether the chain of secondary signatures could be validated successfully
     */
    public boolean isHybridChainValidated() {
        return hybridChainValidated;
    }
}
