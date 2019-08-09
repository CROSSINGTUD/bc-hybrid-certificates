package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.x509.HybridSignature;

import java.io.IOException;

import static org.bouncycastle.utils.ByteArrayUtils.replaceWithZeros;

public class HybridCSRUtils {

    /**
     * Extract the "base csr" from a hybrid csr (the part over which the secondary signature was built)
     *
     * @param csr the complete hybrid csr
     * @return the tbs-part for the secondary signature
     *
     * @throws IOException if there is a problem parsing the extension-data
     */
    public static byte[] extractBaseCSRSearch(PKCS10CertificationRequest csr) throws IOException {
        byte[] base = csr.toASN1Structure().getCertificationRequestInfo().getEncoded();
        byte[] signature = HybridSignature.fromCSR(csr).getSignature();
        replaceWithZeros(base, signature);
        return base;
    }
}
