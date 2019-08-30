package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.HybridCertUtils;
import org.bouncycastle.jcajce.provider.asymmetric.x509.VerifyHelper;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.rmi.server.ExportException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.List;

class HybridValidation {
    private SubjectPublicKeyInfo hybridPublicKey;

    public void validate(CertPath certPath) throws CertPathValidatorException, CertificateEncodingException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        List<? extends Certificate> certificates = certPath.getCertificates();
        for(int j = certificates.size() - 1; j >= 0; --j) {
            validateCert(certificates.get(j), j == certificates.size() - 1, j == 0);
        }
    }

    private void validateCert(Certificate certificate, boolean first, boolean last) throws CertPathValidatorException, IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException {
        X509Certificate cert = (X509Certificate) certificate;
        if (first) {
            try {
                this.hybridPublicKey = HybridKey.fromCert(cert).getKey();
            } catch (Exception e) {
                throw new CertPathValidatorException("Cert does not contain secondary key");
            }
        }
        boolean verify;
        AlgorithmIdentifier algId = getAlgId(cert);

        Signature signature = VerifyHelper.createSignature(algId);
        PublicKey publicKey = BouncyCastlePQCProvider.getPublicKey(hybridPublicKey);
        if (publicKey == null) publicKey = BouncyCastleProvider.getPublicKey(hybridPublicKey);
        signature.initVerify(publicKey);
        signature.update(HybridCertUtils.extractBaseCertSearch(cert));
        verify = signature.verify(HybridSignature.fromCert(cert).getSignature());
        if (!verify) {
            throw new CertPathValidatorException("Unable to validate signature");
        }

        if (!last) {
            try {
                this.hybridPublicKey = HybridKey.fromCert(cert).getKey();
            } catch (Exception e) {
                throw new CertPathValidatorException("Cert does not contain secondary key");
            }
        }
    }

    private AlgorithmIdentifier getAlgId(X509Certificate cert) throws IOException {
        AlgorithmIdentifier algId = HybridSignature.fromCert(cert).getAlgorithmIdentifier();
        if (QTESLAUtils.isQTESLA(algId)) {
            algId = QTESLAUtils.toBCOID(algId);
            hybridPublicKey = QTESLAUtils.toBCSPKI(hybridPublicKey);
        }
        return algId;
    }
}
