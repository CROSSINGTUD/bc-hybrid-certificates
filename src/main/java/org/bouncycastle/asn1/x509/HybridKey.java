package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;

import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * A X509-Extension which contains a secondary public key which is bound to the subject of the certificate.
 * Typically this secondary key will belong to a post-quantum crypto scheme
 */
public class HybridKey extends ASN1Object {

    public static final String OID = "2.5.29.211";
    private SubjectPublicKeyInfo key;

    /**
     * Create a new HybridKey-Extension
     *
     * @param key the public key
     */
    public HybridKey(AsymmetricKeyParameter key) throws IOException {
        this.key = createSubjectPublicKeyInfo(key);
    }

    /**
     * Create a new HybridKey-Extension from a SubjectPublicKeyInfo
     *
     * @param key the public key
     */
    public HybridKey(SubjectPublicKeyInfo key) {
        this.key = key;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return key.toASN1Primitive();
    }

    /**
     * Extract the public key from the extension
     *
     * @return the public key
     */
    public SubjectPublicKeyInfo getKey() {
        return key;
    }

    private static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        if (publicKey instanceof QTESLAPublicKeyParameters) {
            return QTESLAUtils.toSubjectPublicKeyInfo((QTESLAPublicKeyParameters) publicKey);
        } else {
            try {
                return org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
            } catch(IOException ex) {
                return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
            }
        }
    }

    /**
     * Extracts the HybridKey-Extension from a given certificate
     *
     * @param cert the certificate
     * @return the HybridKey-Extension
     */
    public static HybridKey fromCert(X509Certificate cert) throws IOException {
        byte[] data = cert.getExtensionValue(OID);
        ASN1InputStream input = new ASN1InputStream(data);
        ASN1OctetString octstr = ASN1OctetString.getInstance(input.readObject());
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(octstr.getOctets());
        return new HybridKey(subjectPublicKeyInfo);
    }

    /**
     * Extracts the HybridKey-Extension from a given CSR
     *
     * @param csr the CSR
     * @return the HybridKey-Extension
     */
    public static HybridKey fromCSR(PKCS10CertificationRequest csr) throws IOException {
        org.bouncycastle.asn1.pkcs.Attribute[] attr = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attr.length > 0) {
            ASN1Encodable[] encodable = attr[0].getAttributeValues();
            Extensions ext = Extensions.getInstance(encodable[0]);
            byte[] data = ext.getExtension(new ASN1ObjectIdentifier(OID)).getExtnValue().getEncoded();
            ASN1InputStream input = new ASN1InputStream(data);
            ASN1OctetString octstr = ASN1OctetString.getInstance(input.readObject());
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(octstr.getOctets());
            return new HybridKey(subjectPublicKeyInfo);
        } else throw new IOException("no HybridKey extension request");
    }
}
