import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.cert.HybridCertUtils;
import org.bouncycastle.cert.HybridCertificateBuilder;
import org.bouncycastle.cert.HybridSignatureCertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtils;
import org.bouncycastle.jce.provider.HybridCertPathValidatorResult;
import org.bouncycastle.jce.provider.HybridCertPathValidatorSpi;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pqc.crypto.qtesla.*;
import org.bouncycastle.pqc.crypto.util.QTESLAContentSigner;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static utils.Utils.createQTESLAKeyPair;
import static utils.Utils.createRSAKeyPair;

public class HybridSigCertTests {

    @Test
    void testCASig() throws IOException, CertificateException {
        AsymmetricCipherKeyPair CAsecondary = createQTESLAKeyPair(QTESLASecurityCategory.HEURISTIC_I);
        AsymmetricCipherKeyPair CAprimary = createRSAKeyPair();
        AsymmetricCipherKeyPair EEprimary = createRSAKeyPair();
        X509Certificate cert = createHybridSigCertificate("EE", "CA1", EEprimary, CAprimary.getPrivate(), (QTESLAPrivateKeyParameters) CAsecondary.getPrivate());
        assertNotNull(cert);

        // verify primary signature
        KeyPair CAprimaryPair = RSAUtils.toKeyPair(CAprimary);
        assertDoesNotThrow(() -> cert.verify(CAprimaryPair.getPublic()));

        // verify secondary signature
        QTESLASigner verify = new QTESLASigner();
        verify.init(false, CAsecondary.getPublic());
        assertTrue(verify.verifySignature(HybridCertUtils.extractBaseCertSearch(cert), HybridSignature.fromCert(cert).getSignature()));

        // check if primary key in cert is correct
        KeyPair EEprimaryPair = RSAUtils.toKeyPair(EEprimary);
        PublicKey primaryPublic = EEprimaryPair.getPublic();
        PublicKey certPrimary = cert.getPublicKey();
        assertEquals(primaryPublic, certPrimary);
    }

    @Test
    void verifyCertChain() throws CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException {
        AsymmetricCipherKeyPair CA1secondary = createQTESLAKeyPair(QTESLASecurityCategory.HEURISTIC_I);
        AsymmetricCipherKeyPair CA2secondary = createQTESLAKeyPair(QTESLASecurityCategory.HEURISTIC_I);
        AsymmetricCipherKeyPair CA1primary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA2primary = createRSAKeyPair();
        AsymmetricCipherKeyPair EEprimary = createRSAKeyPair();

        X509Certificate CA1cert = createCertificate("CA1", "CA1", CA1primary, CA1secondary, CA1primary.getPrivate(), (QTESLAPrivateKeyParameters) CA1secondary.getPrivate());
        X509Certificate CA2cert = createCertificate("CA2", "CA1", CA2primary, CA2secondary, CA1primary.getPrivate(), (QTESLAPrivateKeyParameters) CA1secondary.getPrivate());
        X509Certificate EEcert = createHybridSigCertificate("EE", "CA2", EEprimary, CA2primary.getPrivate(), (QTESLAPrivateKeyParameters) CA2secondary.getPrivate());
        assertNotNull(CA1cert);
        assertNotNull(CA2cert);
        assertNotNull(EEcert);

        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(EEcert);
        certificates.add(CA2cert);
        certificates.add(CA1cert);

        // verify cert chain
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath certPath = factory.generateCertPath(certificates);
        HybridCertPathValidatorSpi validator = new HybridCertPathValidatorSpi();
        TrustAnchor anchor = new TrustAnchor(certificates.get(certificates.size() - 1), null);
        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(anchor);
        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);
        HybridCertPathValidatorResult result = validator.engineValidate(certPath, params);
        assertTrue(result.isHybridChainValidated());

        assertNull(result.getHybridKey());
    }

    private static X509Certificate createHybridSigCertificate(String subject, String issuer, AsymmetricCipherKeyPair primary, AsymmetricKeyParameter primarySigner, QTESLAPrivateKeyParameters secondarySigner) {
        try {
            DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
            DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
            AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA1withRSA");
            AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);

            Calendar calendar = new GregorianCalendar();

            Date startDate = new Date(); // time from which certificate is valid
            calendar.setTime(startDate);
            calendar.add(Calendar.MONTH, 12);
            Date expiryDate = calendar.getTime(); // time after which certificate is not valid

            BigInteger serialNumber = new BigInteger("1234"); // serial number for certificate

            X500Name subjectName = new X500Name("CN=" + subject + ", C=DE");
            X500Name issuerName = new X500Name("CN=" + issuer + ", C=DE");

            HybridSignatureCertificateBuilder certificateBuilder = new HybridSignatureCertificateBuilder(
                    issuerName,
                    serialNumber,
                    startDate,
                    expiryDate,
                    subjectName,
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(primary.getPublic())
            );
            certificateBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), false, new BasicConstraints(true));

            ContentSigner sigPrimary = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(primarySigner);
            ContentSigner sigSecondary = new QTESLAContentSigner(secondarySigner);

            X509CertificateHolder x509CertificateHolder = certificateBuilder.buildHybrid(sigPrimary, sigSecondary);
            return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static X509Certificate createCertificate(String subject, String issuer, AsymmetricCipherKeyPair primary, AsymmetricCipherKeyPair secondary, AsymmetricKeyParameter primarySigner, QTESLAPrivateKeyParameters secondarySigner) {
        try {
            DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
            DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
            AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA1withRSA");
            AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);

            Calendar calendar = new GregorianCalendar();

            Date startDate = new Date(); // time from which certificate is valid
            calendar.setTime(startDate);
            calendar.add(Calendar.MONTH, 12);
            Date expiryDate = calendar.getTime(); // time after which certificate is not valid

            BigInteger serialNumber = new BigInteger("1234"); // serial number for certificate

            X500Name subjectName = new X500Name("CN=" + subject + ", C=DE");
            X500Name issuerName = new X500Name("CN=" + issuer + ", C=DE");

            HybridCertificateBuilder certificateBuilder = new HybridCertificateBuilder(
                    issuerName,
                    serialNumber,
                    startDate,
                    expiryDate,
                    subjectName,
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(primary.getPublic()),
                    secondary.getPublic()
            );
            certificateBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), false, new BasicConstraints(true));

            ContentSigner sigPrimary = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(primarySigner);
            ContentSigner sigSecondary = new QTESLAContentSigner(secondarySigner);

            X509CertificateHolder x509CertificateHolder = certificateBuilder.buildHybrid(sigPrimary, sigSecondary);
            return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
