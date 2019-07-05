package org.bouncycastle.pqc.crypto.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * A XMSS content signer
 */
public class XMSSContentSigner implements ContentSigner {

    private AlgorithmIdentifier algId;
    private ByteArrayOutputStream stream;
    private XMSSSigner signer;

    /**
     * Create a new XMSS content singer
     * @param privateKey the private key
     */
    public XMSSContentSigner(XMSSPrivateKeyParameters privateKey) {
        algId = new AlgorithmIdentifier(lookupAlgId(privateKey.getTreeDigest()));
        this.signer = new XMSSSigner();
        this.signer.init(true, privateKey);
        this.stream = new ByteArrayOutputStream();
    }

    private static ASN1ObjectIdentifier lookupAlgId(String treeDigest)
    {
        switch (treeDigest) {
            case XMSSKeyParameters.SHA_256:
                return PQCObjectIdentifiers.xmss_SHA256;
            case XMSSKeyParameters.SHA_512:
                return PQCObjectIdentifiers.xmss_SHA512;
            case XMSSKeyParameters.SHAKE128:
                return PQCObjectIdentifiers.xmss_SHAKE128;
            case XMSSKeyParameters.SHAKE256:
                return PQCObjectIdentifiers.xmss_SHAKE256;
            default:
                throw new IllegalArgumentException("unknown tree digest: " + treeDigest);
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algId;
    }

    @Override
    public OutputStream getOutputStream() {
        return stream;
    }

    @Override
    public byte[] getSignature() {
        return signer.generateSignature(stream.toByteArray());
    }
}
