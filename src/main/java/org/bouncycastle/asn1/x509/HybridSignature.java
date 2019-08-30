package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.BitSet;

import static org.bouncycastle.utils.ByteBoolConverter.booleanToByte;

/**
 * A X509-Extension which contains a secondary signature, which provides an additional binding between
 * the certificate subject and the key(s)
 * Typically this secondary signature will belong to a post-quantum crypto scheme
 */
public class HybridSignature extends ASN1Object {

    public static final String OID = "2.5.29.212";
    private byte[] signature;
    private AlgorithmIdentifier algId;

    /**
     * Create a new HybridSignature-Extension
     *
     * @param signature the signature
     * @param algId the AlgId of the signature
     */
    public HybridSignature(byte[] signature, AlgorithmIdentifier algId) {
        this.signature = signature;
        this.algId = algId;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(algId);
        v.add(new DERBitString(signature));
        return new DERSequence(v);
    }

    /**
     * Query the signature from the extension
     *
     * @return the signature bytes
     */
    public byte[] getSignature() {
        return signature;
    }

    /**
     * Query the AlgId from the extension
     *
     * @return the AlgId of the signature
     */
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algId;
    }

    /**
     * Extract the HybridSignature-Extension from a certificate
     *
     * @param cert the certificate
     * @return the HybridSignature-Extension
     *
     * @throws IOException if there is a problem parsing the extension-data
     */
    public static HybridSignature fromCert(X509Certificate cert) throws IOException {
        boolean[] bool = cert.getSubjectUniqueID();
        byte[] data = booleanToByte(bool);
        ASN1Sequence seq2 = (ASN1Sequence) ASN1Sequence.fromByteArray(data);
        ASN1Sequence seq = (ASN1Sequence) seq2.getObjectAt(1);
        AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        ASN1BitString sig = (ASN1BitString) seq.getObjectAt(1);
        return new HybridSignature(sig.getOctets(), algId);
    }
}
