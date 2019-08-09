package org.bouncycastle.cert;

import org.bouncycastle.asn1.x509.HybridSignature;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.bouncycastle.utils.ByteArrayUtils.replaceWithZeros;

public class HybridCertUtils {

    /**
     * Extract the "base cert" from a hybrid certificate (the part over which the secondary signature was built)
     *
     * @param cert the complete hybrid certificate
     * @return the tbs-part for the secondary signature
     *
     * @throws IOException if there is a problem parsing the extension-data
     * @throws CertificateEncodingException on encoding error in the certificate
     */
    public static byte[] extractBaseCertSearch(X509Certificate cert) throws IOException,CertificateEncodingException {
        byte[] base = cert.getTBSCertificate();
        byte[] signature = HybridSignature.fromCert(cert).getSignature();
        replaceWithZeros(base, signature);
        return base;
    }
}
