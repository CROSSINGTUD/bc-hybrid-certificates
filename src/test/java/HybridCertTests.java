import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.HybridKey;
import org.bouncycastle.asn1.x509.HybridSignature;
import org.bouncycastle.cert.HybridCertUtils;
import org.bouncycastle.cert.HybridCertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtils;
import org.bouncycastle.jce.provider.HybridCertPathValidatorResult;
import org.bouncycastle.jce.provider.HybridCertPathValidatorSpi;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pqc.crypto.qtesla.*;
import org.bouncycastle.pqc.crypto.util.QTESLAContentSigner;
import org.bouncycastle.pqc.crypto.util.XMSSContentSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import utils.QTeslaSecurityCategory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import static org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory.*;
import static org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils.fromSubjectPublicKeyInfo;
import static org.junit.jupiter.api.Assertions.*;
import static utils.Utils.*;

public class HybridCertTests {


    @DisplayName("Test self signed certificates with qTESLA secondary signature")
    @ParameterizedTest
    @EnumSource(value = QTeslaSecurityCategory.class)
    void testSelfSigQTESLA(QTeslaSecurityCategory qteslaSecurityCategory) throws IOException, CertificateException {
        AsymmetricCipherKeyPair secondary = createQTESLAKeyPair(qteslaSecurityCategory.getValue());
        AsymmetricCipherKeyPair primary = createRSAKeyPair();

        ContentSigner secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) secondary.getPrivate());
        X509Certificate cert = createCertificate("CA1", "CA1", primary, secondary, primary.getPrivate(), secondarySigner);
        assertNotNull(cert);

        // verify primary signature
        KeyPair primaryPair = RSAUtils.toKeyPair(primary);
        assertDoesNotThrow(() -> cert.verify(primaryPair.getPublic()));

        // verify secondary signature
        QTESLASigner verify = new QTESLASigner();
        verify.init(false, secondary.getPublic());
        assertTrue(verify.verifySignature(HybridCertUtils.extractBaseCertSearch(cert), HybridSignature.fromCert(cert).getSignature()));

        // check if primary key in cert is correct
        PublicKey primaryPublic = primaryPair.getPublic();
        PublicKey certPrimary = cert.getPublicKey();
        assertEquals(primaryPublic, certPrimary);

        // check if secondary key in cert is correct
        QTESLAPublicKeyParameters secondaryPublic = (QTESLAPublicKeyParameters) secondary.getPublic();
        QTESLAPublicKeyParameters certSecondary = fromSubjectPublicKeyInfo(HybridKey.fromCert(cert).getKey());
        assertArrayEquals(certSecondary.getPublicData(), secondaryPublic.getPublicData());
        assertEquals(certSecondary.getSecurityCategory(), secondaryPublic.getSecurityCategory());
    }

    @DisplayName("Test CA signed certificates with qTESLA secondary signature")
    @ParameterizedTest
    @EnumSource(value = QTeslaSecurityCategory.class)
    void caSigQTESLA(QTeslaSecurityCategory qteslaSecurityCategory) throws IOException, CertificateException {
        AsymmetricCipherKeyPair CAsecondary = createQTESLAKeyPair(qteslaSecurityCategory.getValue());
        AsymmetricCipherKeyPair CAprimary = createRSAKeyPair();
        AsymmetricCipherKeyPair EEsecondary = createQTESLAKeyPair(qteslaSecurityCategory.getValue());
        AsymmetricCipherKeyPair EEprimary = createRSAKeyPair();
        ContentSigner secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CAsecondary.getPrivate());
        X509Certificate cert = createCertificate("EE", "CA1", EEprimary, EEsecondary, CAprimary.getPrivate(), secondarySigner);
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

        // check if secondary key in cert is correct
        QTESLAPublicKeyParameters secondaryPublic = (QTESLAPublicKeyParameters) EEsecondary.getPublic();
        QTESLAPublicKeyParameters certSecondary = fromSubjectPublicKeyInfo(HybridKey.fromCert(cert).getKey());
        assertArrayEquals(certSecondary.getPublicData(), secondaryPublic.getPublicData());
        assertEquals(certSecondary.getSecurityCategory(), secondaryPublic.getSecurityCategory());
    }

    @DisplayName("Test certificate chains with qTESLA secondary signatures")
    @ParameterizedTest
    @EnumSource(value = QTeslaSecurityCategory.class)
    void testCertChainQTESLA(QTeslaSecurityCategory securityCategory) throws CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException {
        AsymmetricCipherKeyPair CA1secondary = createQTESLAKeyPair(securityCategory.getValue());
        AsymmetricCipherKeyPair CA2secondary = createQTESLAKeyPair(securityCategory.getValue());
        AsymmetricCipherKeyPair EEsecondary = createQTESLAKeyPair(securityCategory.getValue());
        AsymmetricCipherKeyPair CA1primary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA2primary = createRSAKeyPair();
        AsymmetricCipherKeyPair EEprimary = createRSAKeyPair();

        ContentSigner secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CA1secondary.getPrivate());
        X509Certificate CA1cert = createCertificate("CA1", "CA1", CA1primary, CA1secondary, CA1primary.getPrivate(), secondarySigner);
        secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CA1secondary.getPrivate());
        X509Certificate CA2cert = createCertificate("CA2", "CA1", CA2primary, CA2secondary, CA1primary.getPrivate(), secondarySigner);
        secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CA2secondary.getPrivate());
        X509Certificate EEcert = createCertificate("EE", "CA2", EEprimary, EEsecondary, CA2primary.getPrivate(), secondarySigner);
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

        // check key returned from cert chain validation

        QTESLAPublicKeyParameters lastKey = (QTESLAPublicKeyParameters) result.getHybridKey();
        QTESLAPublicKeyParameters EEsecondaryPublic = (QTESLAPublicKeyParameters) EEsecondary.getPublic();
        assertArrayEquals(lastKey.getPublicData(), EEsecondaryPublic.getPublicData());
        assertEquals(lastKey.getSecurityCategory(), EEsecondaryPublic.getSecurityCategory());
    }


    @DisplayName("Test longer certificate chain with qTESLA secondary signatures")
    @Test
    void testCertChainQTESLALong() throws CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException {
        AsymmetricCipherKeyPair CA1secondary = createQTESLAKeyPair(PROVABLY_SECURE_III);
        AsymmetricCipherKeyPair CA2secondary = createQTESLAKeyPair(PROVABLY_SECURE_I);
        AsymmetricCipherKeyPair CA3secondary = createQTESLAKeyPair(HEURISTIC_III_SIZE);
        AsymmetricCipherKeyPair CA4secondary = createQTESLAKeyPair(HEURISTIC_III_SPEED);
        AsymmetricCipherKeyPair EEsecondary = createQTESLAKeyPair(HEURISTIC_I);
        AsymmetricCipherKeyPair CA1primary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA2primary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA3primary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA4primary = createRSAKeyPair();
        AsymmetricCipherKeyPair EEprimary = createRSAKeyPair();

        ContentSigner secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CA1secondary.getPrivate());
        X509Certificate CA1cert = createCertificate("CA1", "CA1", CA1primary, CA1secondary, CA1primary.getPrivate(), secondarySigner);
        secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CA1secondary.getPrivate());
        X509Certificate CA2cert = createCertificate("CA2", "CA1", CA2primary, CA2secondary, CA1primary.getPrivate(), secondarySigner);
        secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CA2secondary.getPrivate());
        X509Certificate CA3cert = createCertificate("CA3", "CA2", CA3primary, CA3secondary, CA2primary.getPrivate(), secondarySigner);
        secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CA3secondary.getPrivate());
        X509Certificate CA4cert = createCertificate("CA4", "CA3", CA4primary, CA4secondary, CA3primary.getPrivate(), secondarySigner);
        secondarySigner = new QTESLAContentSigner((QTESLAPrivateKeyParameters) CA4secondary.getPrivate());
        X509Certificate EEcert = createCertificate("EE", "CA4", EEprimary, EEsecondary, CA4primary.getPrivate(), secondarySigner);
        assertNotNull(CA1cert);
        assertNotNull(CA2cert);
        assertNotNull(CA3cert);
        assertNotNull(CA4cert);
        assertNotNull(EEcert);

        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(EEcert);
        certificates.add(CA4cert);
        certificates.add(CA3cert);
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

        // check key returned from cert chain validation

        QTESLAPublicKeyParameters lastKey = (QTESLAPublicKeyParameters) result.getHybridKey();
        QTESLAPublicKeyParameters EEsecondaryPublic = (QTESLAPublicKeyParameters) EEsecondary.getPublic();
        assertArrayEquals(lastKey.getPublicData(), EEsecondaryPublic.getPublicData());
        assertEquals(lastKey.getSecurityCategory(), EEsecondaryPublic.getSecurityCategory());
    }

    @DisplayName("Test certificate chain with RSA secondary signatures")
    @Test
    void testCertChainRSA() throws CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException, OperatorCreationException {
        AsymmetricCipherKeyPair CA1secondary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA2secondary = createRSAKeyPair();
        AsymmetricCipherKeyPair EEsecondary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA1primary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA2primary = createRSAKeyPair();
        AsymmetricCipherKeyPair EEprimary = createRSAKeyPair();

        DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier sigAlg = sigAlgFinder.find("SHA1withRSA");
        AlgorithmIdentifier digAlg = digAlgFinder.find(sigAlg);
        ContentSigner secondarySigner = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(CA1secondary.getPrivate());
        X509Certificate CA1cert = createCertificate("CA1", "CA1", CA1primary, CA1secondary, CA1primary.getPrivate(), secondarySigner);
        secondarySigner = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(CA1secondary.getPrivate());
        X509Certificate CA2cert = createCertificate("CA2", "CA1", CA2primary, CA2secondary, CA1primary.getPrivate(), secondarySigner);
        secondarySigner = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(CA2secondary.getPrivate());
        X509Certificate EEcert = createCertificate("EE", "CA2", EEprimary, EEsecondary, CA2primary.getPrivate(), secondarySigner);
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

        // check key returned from cert chain validation

        RSAKeyParameters lastKey = (RSAKeyParameters) result.getHybridKey();
        RSAKeyParameters EEsecondaryPublic = (RSAKeyParameters) EEsecondary.getPublic();
        assertEquals(lastKey.getModulus(), EEsecondaryPublic.getModulus());
        assertEquals(lastKey.getExponent(), EEsecondaryPublic.getExponent());
    }

    @DisplayName("Test certificate chain with XMSS secondary signatures")
    @Test
    void testCertChainXMSS() throws CertificateException, InvalidAlgorithmParameterException, CertPathValidatorException, OperatorCreationException {
        AsymmetricCipherKeyPair CA1secondary = createXMSSKeyPair();
        AsymmetricCipherKeyPair CA2secondary = createXMSSKeyPair();
        AsymmetricCipherKeyPair EEsecondary = createXMSSKeyPair();
        AsymmetricCipherKeyPair CA1primary = createRSAKeyPair();
        AsymmetricCipherKeyPair CA2primary = createRSAKeyPair();
        AsymmetricCipherKeyPair EEprimary = createRSAKeyPair();

        ContentSigner secondarySigner = new XMSSContentSigner((XMSSPrivateKeyParameters) CA1secondary.getPrivate());
        X509Certificate CA1cert = createCertificate("CA1", "CA1", CA1primary, CA1secondary, CA1primary.getPrivate(), secondarySigner);
        secondarySigner = new XMSSContentSigner((XMSSPrivateKeyParameters) CA1secondary.getPrivate());
        X509Certificate CA2cert = createCertificate("CA2", "CA1", CA2primary, CA2secondary, CA1primary.getPrivate(), secondarySigner);
        secondarySigner = new XMSSContentSigner((XMSSPrivateKeyParameters) CA2secondary.getPrivate());
        X509Certificate EEcert = createCertificate("EE", "CA2", EEprimary, EEsecondary, CA2primary.getPrivate(), secondarySigner);
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

        // check key returned from cert chain validation

        XMSSPublicKeyParameters lastKey = (XMSSPublicKeyParameters) result.getHybridKey();
        XMSSPublicKeyParameters EEsecondaryPublic = (XMSSPublicKeyParameters) EEsecondary.getPublic();
        assertArrayEquals(lastKey.getPublicSeed(), EEsecondaryPublic.getPublicSeed());
        assertArrayEquals(lastKey.getRoot(), EEsecondaryPublic.getRoot());
    }



    private static X509Certificate createCertificate(String subject, String issuer, AsymmetricCipherKeyPair primary, AsymmetricCipherKeyPair secondary, AsymmetricKeyParameter primarySigner, ContentSigner secondarySigner) {
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

            X509CertificateHolder x509CertificateHolder = certificateBuilder.buildHybrid(sigPrimary, secondarySigner);
            return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
