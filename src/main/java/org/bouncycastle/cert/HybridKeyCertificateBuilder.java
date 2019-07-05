package org.bouncycastle.cert;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Helper class for creating (partly) hybrid certificates, which contain a secondary public key
 */
public class HybridKeyCertificateBuilder extends X509v3CertificateBuilder {
    private AsymmetricKeyParameter secondary;

    /**
     * Create a builder for a hybrid-key version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param primary the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridKeyCertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo primary, AsymmetricKeyParameter secondary) {
        super(issuer, serial, notBefore, notAfter, subject, primary);
        this.secondary = secondary;
    }

    /**
     * Create a builder for a hybrid-key version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridKeyCertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey, AsymmetricKeyParameter secondary) {
        this(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), secondary);
    }

    /**
     * Create a builder for a hybrid-key version 3 certificate.
     *
     * @param issuer the certificate issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridKeyCertificateBuilder(X500Principal issuer, BigInteger serial, Date notBefore, Date notAfter, X500Principal subject, PublicKey publicKey, AsymmetricKeyParameter secondary) {
        this(X500Name.getInstance(issuer.getEncoded()), serial, notBefore, notAfter, X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), secondary);
    }

    /**
     * Create a builder for a hybrid-key version 3 certificate.
     *
     * @param issuerCert the certificate of the issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridKeyCertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Principal subject, PublicKey publicKey, AsymmetricKeyParameter secondary) {
        this(issuerCert.getSubjectX500Principal(), serial, notBefore, notAfter, subject, publicKey, secondary);
    }

    /**
     * Create a builder for a hybrid-key version 3 certificate.
     *
     * @param issuerCert the certificate of the issuer
     * @param serial the certificate serial number
     * @param notBefore the date before which the certificate is not valid
     * @param notAfter the date after which the certificate is not valid
     * @param subject the certificate subject
     * @param publicKey the public key to be associated with this certificate.
     * @param secondary the second (hybrid) public key to be associated with this certificate
     */
    public HybridKeyCertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey, AsymmetricKeyParameter secondary) {
        this(X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded()), serial, notBefore, notAfter, subject, publicKey, secondary);
    }

    @Override
    public X509CertificateHolder build(ContentSigner primary) {
        throw new UnsupportedOperationException();
    }

    /**
     * Generate a hybrid-key X.509 certificate, based on the current issuer and subject using the passed in signer.
     *
     * @param primary the content signer to be used to generate the signature validating the certificate
     * @return a holder containing the resulting signed hybrid-key certificate
     */
    public X509CertificateHolder buildHybrid(ContentSigner primary) throws IOException {
        addExtension(new ASN1ObjectIdentifier(HybridKey.OID), false, new HybridKey(this.secondary));
        return super.build(primary);
    }
}
