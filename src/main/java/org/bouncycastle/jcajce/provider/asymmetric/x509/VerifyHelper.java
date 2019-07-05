package org.bouncycastle.jcajce.provider.asymmetric.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.*;

public class VerifyHelper {

    /**
     * Create a Signature object for the given algorithm identifier
     *
     * @param algId the algorithm identifier
     * @return a signature object for the given algorithm
     */
    public static Signature createSignature(AlgorithmIdentifier algId) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String sigName = X509SignatureUtil.getSignatureName(algId);
        Signature signature;
        try {
            signature = Signature.getInstance(sigName, new BouncyCastlePQCProvider());
        } catch (NoSuchAlgorithmException ex) {
            signature = Signature.getInstance(sigName, new BouncyCastleProvider());
        }
        ASN1Encodable params = algId.getParameters();
        X509SignatureUtil.setSignatureParameters(signature, params);
        return signature;
    }
}
