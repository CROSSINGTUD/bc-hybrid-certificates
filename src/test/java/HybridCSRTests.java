import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.HybridCSRBuilder;
import org.bouncycastle.pkcs.HybridCSRUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pqc.crypto.qtesla.*;
import org.bouncycastle.pqc.crypto.util.QTESLAContentSigner;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils.fromSubjectPublicKeyInfo;
import static org.junit.jupiter.api.Assertions.*;
import static utils.Utils.createQTESLAKeyPair;
import static utils.Utils.createRSAKeyPair;

public class HybridCSRTests {

    @Test
    void testCSR() throws Exception {
        AsymmetricCipherKeyPair secondary = createQTESLAKeyPair(QTESLASecurityCategory.HEURISTIC_I);
        AsymmetricCipherKeyPair primary = createRSAKeyPair();
        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA1withRSA");
        AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);
        HybridCSRBuilder builder = new HybridCSRBuilder(new X500Name("CN=EE"), SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(primary.getPublic()), secondary.getPublic());
        ContentSigner sigPrimary = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(primary.getPrivate());
        ContentSigner sigSecondary = new QTESLAContentSigner((QTESLAPrivateKeyParameters) secondary.getPrivate());
        PKCS10CertificationRequest csr = builder.buildHybrid(sigPrimary, sigSecondary);
        assertNotNull(csr);

        // verify primary signature
        KeyPair primaryPair = RSAUtils.toKeyPair(primary);
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(primaryPair.getPublic());
        assertTrue(csr.isSignatureValid(verifier));

        // verify secondary signature
        QTESLASigner verify = new QTESLASigner();
        verify.init(false, secondary.getPublic());
        assertTrue(verify.verifySignature(HybridCSRUtils.extractBaseCSRSearch(csr), HybridSignature.fromCSR(csr).getSignature()));

        // check if primary key in csr is correct
        PublicKey primaryPublic = primaryPair.getPublic();
        PublicKey csrPrimary = getKeyFromCSR(csr);
        assertEquals(primaryPublic, csrPrimary);

        // check if secondary key in csr is correct
        QTESLAPublicKeyParameters secondaryPublic = (QTESLAPublicKeyParameters) secondary.getPublic();
        QTESLAPublicKeyParameters csrSecondary = fromSubjectPublicKeyInfo(HybridKey.fromCSR(csr).getKey());
        assertArrayEquals(csrSecondary.getPublicData(), secondaryPublic.getPublicData());
        assertEquals(csrSecondary.getSecurityCategory(), secondaryPublic.getSecurityCategory());
    }

    private static PublicKey getKeyFromCSR(PKCS10CertificationRequest csr) throws Exception {
        try {
            return new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());
        } catch (Exception e) {
            throw new Exception("failed to get key from CSR: " + e.getMessage() + " (" + e.getClass().getSimpleName() + ")");
        }
    }
}
