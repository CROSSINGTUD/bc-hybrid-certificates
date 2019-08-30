package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.*;

public class HybridCertPathValidatorSpi extends PKIXCertPathValidatorSpi {

    @Override
    public HybridCertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params) throws CertPathValidatorException, InvalidAlgorithmParameterException {
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) super.engineValidate(certPath, params);

        HybridValidation hybridValidation = new HybridValidation();
        try {
            hybridValidation.validate(certPath);
        } catch (CertPathValidatorException | CertificateEncodingException | SignatureException | NoSuchAlgorithmException | InvalidKeyException | IOException exception) {
            return new HybridCertPathValidatorResult(result, null, false);
        }
        X509Certificate cert = (X509Certificate) certPath.getCertificates().get(0);

        try {
            SubjectPublicKeyInfo hybridKey = HybridKey.fromCert(cert).getKey();
            try {
                AsymmetricKeyParameter key;
                if (QTESLAUtils.isQTESLA(hybridKey.getAlgorithm()))
                    key = QTESLAUtils.fromSubjectPublicKeyInfo(hybridKey);
                else {
                    try {
                        key = org.bouncycastle.pqc.crypto.util.PublicKeyFactory.createKey(hybridKey);
                    } catch (IOException ex) {
                        key = org.bouncycastle.crypto.util.PublicKeyFactory.createKey(hybridKey);
                    }
                }
                return new HybridCertPathValidatorResult(result, key, true);
            } catch (IOException e) {
                throw new CertPathValidatorException(e.getMessage());
            }
        } catch (Exception e) {
            return new HybridCertPathValidatorResult(result, null, true);
        }
    }
}
