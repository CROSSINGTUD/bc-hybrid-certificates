package org.bouncycastle.pqc.crypto.util;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * A qTESLA content signer
 */
public class QTESLAContentSigner implements ContentSigner {

    private AlgorithmIdentifier algId;
    private ByteArrayOutputStream stream;
    private QTESLASigner signer;

    /**
     * Create a new qTESLA content singer
     * @param privateKey the private key
     */
    public QTESLAContentSigner(QTESLAPrivateKeyParameters privateKey) {
        algId = QTESLAUtils.getAlgorithmIdentifier(privateKey.getSecurityCategory());
        this.signer = new QTESLASigner();
        this.signer.init(true, privateKey);
        this.stream = new ByteArrayOutputStream();
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
