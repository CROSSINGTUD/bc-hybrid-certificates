package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.ContentSigner;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;

/**
 * Helper class for creating hybrid CSRs
 */
public class HybridCSRBuilder {

    private AsymmetricKeyParameter secondary;
    private PKCS10CertificationRequestBuilder builder;
    private ExtensionsGenerator extGen;

    /**
     * Create a builder for a hybrid CSR.
     *
     * @param subject the subject of the CSR
     * @param publicKeyInfo the public key to be associated with this CSR
     * @param secondary the secondary (hybrid) public key to be associated with this CSR
     */
    public HybridCSRBuilder(X500Name subject, SubjectPublicKeyInfo publicKeyInfo, AsymmetricKeyParameter secondary) {
        this.builder = new PKCS10CertificationRequestBuilder(subject, publicKeyInfo);
        this.secondary = secondary;
        extGen = new ExtensionsGenerator();
    }

    /**
     * Create a builder for a hybrid CSR.
     *
     * @param subject the subject of the CSR
     * @param primary the public key to be associated with this CSR
     * @param secondary the secondary (hybrid) public key to be associated with this CSR
     */
    public HybridCSRBuilder(X500Name subject, PublicKey primary, AsymmetricKeyParameter secondary) {
        this(subject, SubjectPublicKeyInfo.getInstance(primary.getEncoded()), secondary);
    }

    /**
     * Create a builder for a hybrid CSR.
     *
     * @param subject the subject of the CSR
     * @param primary the public key to be associated with this CSR
     * @param secondary the secondary (hybrid) public key to be associated with this CSR
     */
    public HybridCSRBuilder(X500Principal subject, PublicKey primary, AsymmetricKeyParameter secondary) {
        this(X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(primary.getEncoded()), secondary);
    }

    /**
     * Adds an "extension-request" to the CSR. This means the CA is asked to include this extension into the certificate
     *
     * @param oid the object identifier of the extension
     * @param isCritical whether the extension should be critical
     * @param value the extension value
     */
    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value) throws IOException {
        this.extGen.addExtension(oid, isCritical, value);
    }

    /**
     * Adds an "extension-request" to the CSR. This means the CA is asked to include this extension into the certificate
     *
     * @param extension the extension
     */
    public void addExtension(Extension extension) {
        this.extGen.addExtension(extension);
    }

    /**
     * Adds an "extension-request" to the CSR. This means the CA is asked to include this extension into the certificate
     *
     * @param oid the object identifier of the extension
     * @param isCritical whether the extension should be critical
     * @param encodedValue the byte value of the extension
     */
    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, byte[] encodedValue) {
        this.extGen.addExtension(oid, isCritical, encodedValue);
    }

    private CertificationRequestInfo prepareForHybrid(ContentSigner primary, int secondarySigSize, AlgorithmIdentifier secondaryAlgId) throws IOException {
        addExtension(new ASN1ObjectIdentifier(HybridKey.OID), false, new HybridKey(this.secondary));
        byte[] zeros = new byte[secondarySigSize];
        addExtension(new ASN1ObjectIdentifier(HybridSignature.OID), false, new HybridSignature(zeros, secondaryAlgId));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        PKCS10CertificationRequest csr = builder.build(primary);
        return csr.toASN1Structure().getCertificationRequestInfo();
    }

    /**
     * Generate a hybrid CSR, based on the current issuer and subject using the passed in signer.
     *
     * @param primary the content signer to be used to generate the signature validating the certificate
     * @param secondary the message signer to be used to generate the secondary (hybrid) signature
     * @return the resulting, signed CSR
     */
    public PKCS10CertificationRequest buildHybrid(ContentSigner primary, ContentSigner secondary) throws IOException {
        int secondarySigSize = secondary.getSignature().length;
        CertificationRequestInfo tbs = prepareForHybrid(primary, secondarySigSize, secondary.getAlgorithmIdentifier());
        secondary.getOutputStream().write(tbs.toASN1Primitive().getEncoded());
        byte[] signature = secondary.getSignature();
        byte[] bytes = tbs.getEncoded();
        System.arraycopy(signature, 0, bytes, bytes.length - secondarySigSize, secondarySigSize);
        CertificationRequestInfo info = CertificationRequestInfo.getInstance(bytes);
        OutputStream sOut = primary.getOutputStream();
        sOut.write(info.getEncoded("DER"));
        sOut.close();
        return new PKCS10CertificationRequest(new CertificationRequest(info, primary.getAlgorithmIdentifier(), new DERBitString(primary.getSignature())));
    }
}
