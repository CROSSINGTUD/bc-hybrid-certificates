package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Helper class for creating (partly) hybrid certificates, which contain a secondary signature
 */
public class HybridSignatureCertificateBuilder extends X509v3CertificateBuilder {

    /**
     * Create a builder for a hybrid-signature version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param primary the public key to be associated with this certificate.
     */
    public HybridSignatureCertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo primary) {
        super(issuer, serial, notBefore, notAfter, subject, primary);
    }

    /**
     * Create a builder for a hybrid-signature version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     */
    public HybridSignatureCertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey) {
        this(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    /**
     * Create a builder for a hybrid-signature version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     */
    public HybridSignatureCertificateBuilder(X500Principal issuer, BigInteger serial, Date notBefore, Date notAfter, X500Principal subject, PublicKey publicKey) {
        this(X500Name.getInstance(issuer.getEncoded()), serial, notBefore, notAfter, X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    /**
     * Create a builder for a hybrid version 3 certificate.
     *
     * @param issuerCert the certificate of the issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     */
    public HybridSignatureCertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Principal subject, PublicKey publicKey) {
        this(issuerCert.getSubjectX500Principal(), serial, notBefore, notAfter, subject, publicKey);
    }

    /**
     * Create a builder for a hybrid-signature version 3 certificate.
     *
     * @param issuerCert the certificate of the issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     */
    public HybridSignatureCertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey) {
        this(X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded()), serial, notBefore, notAfter, subject, publicKey);
    }

    protected TBSCertificate prepareForHybrid(ContentSigner primary, int secondarySigSize, AlgorithmIdentifier secondaryAlgId) throws IOException {
        byte[] zeros = new byte[secondarySigSize];
        addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(zeros, secondaryAlgId));
        X509CertificateHolder cert = super.build(primary);
        return cert.toASN1Structure().getTBSCertificate();
    }

    @Override
    public X509CertificateHolder build(ContentSigner primary) {
        throw new UnsupportedOperationException();
    }

    /**
     * Generate a hybrid X.509 certificate, based on the current issuer and subject using the passed in signer.
     *
     * @param primary the content signer to be used to generate the signature validating the certificate
     * @param secondary the message signer to be used to generate the secondary (hybrid) signature
     * @return a holder containing the resulting signed hybrid certificate
     */
    public X509CertificateHolder buildHybrid(ContentSigner primary, ContentSigner secondary) throws IOException {
        int secondarySigSize = secondary.getSignature().length;
        TBSCertificate tbs = prepareForHybrid(primary, secondarySigSize, secondary.getAlgorithmIdentifier());
        byte[] bytes = null;
        secondary.getOutputStream().write(tbs.toASN1Primitive().getEncoded());
        byte[] signature = secondary.getSignature();
        bytes = tbs.getEncoded();
        System.arraycopy(signature, 0, bytes, bytes.length - secondarySigSize, secondarySigSize);
        return CertUtils.generateFullCert(primary, TBSCertificate.getInstance(bytes));
    }
}
