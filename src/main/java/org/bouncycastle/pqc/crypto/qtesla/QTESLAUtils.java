package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;

import java.io.IOException;

/**
 * Helper functions for qTESLA(-keys)
 */
public class QTESLAUtils {

    /**
     * OIDs for different modes of qTESLA
     */
    private static final String OID_HEURISTIC_I = "1.3.6.1.4.1.311.89.2.2.1";
    private static final String OID_HEURISTIC_III_SIZE = "1.3.6.1.4.1.311.89.2.2.2";
    private static final String OID_HEURISTIC_III_SPEED = "1.3.6.1.4.1.311.89.2.2.3";
    private static final String OID_PROVABLY_SECURE_I = "1.3.6.1.4.1.311.89.2.2.4";
    private static final String OID_PROVABLY_SECURE_III = "1.3.6.1.4.1.311.89.2.2.5";



    /**
     * Extract a qTESLA public key from a SubjectPublicKeyInfo object
     *
     * @param key the SubjectPublicKeyInfo
     * @return the public key
     */
    public static QTESLAPublicKeyParameters fromSubjectPublicKeyInfo(SubjectPublicKeyInfo key) {
        byte[] data = key.getPublicKeyData().getOctets();
        return new QTESLAPublicKeyParameters(getSecurityCategory(key.getAlgorithm()), data);
    }

    public static SubjectPublicKeyInfo toSubjectPublicKeyInfo(QTESLAPublicKeyParameters publicKey) {
        AlgorithmIdentifier algId = QTESLAUtils.getAlgorithmIdentifier(publicKey.getSecurityCategory());
        return new SubjectPublicKeyInfo(algId, publicKey.getPublicData());
    }

    /**
     * Check if the given AlgID is qTESLA
     *
     * @param algId the algorithm identifier
     * @return true if the AlgID belongs to qTESLA, false otherwise
     */
    public static boolean isQTESLA(AlgorithmIdentifier algId) {
        String oid = algId.getAlgorithm().getId();
        return oid.equals(OID_HEURISTIC_I) || oid.equals(OID_HEURISTIC_III_SIZE) || oid.equals(OID_HEURISTIC_III_SPEED) || oid.equals(OID_PROVABLY_SECURE_I) || oid.equals(OID_PROVABLY_SECURE_III);
    }

    public static AlgorithmIdentifier toBCOID(AlgorithmIdentifier algorithmIdentifier) {
        ASN1ObjectIdentifier oid;
        switch(algorithmIdentifier.getAlgorithm().getId()) {
            case OID_HEURISTIC_I:
                oid = PQCObjectIdentifiers.qTESLA_I;
                break;
            case OID_HEURISTIC_III_SIZE:
                oid = PQCObjectIdentifiers.qTESLA_III_size;
                break;
            case OID_HEURISTIC_III_SPEED:
                oid = PQCObjectIdentifiers.qTESLA_III_speed;
                break;
            case OID_PROVABLY_SECURE_I:
                oid = PQCObjectIdentifiers.qTESLA_p_I;
                break;
            case OID_PROVABLY_SECURE_III:
                oid = PQCObjectIdentifiers.qTESLA_p_III;
                break;
            default: throw new RuntimeException("no qTESLA OID");
        }
        return new AlgorithmIdentifier(oid);
    }

    public static SubjectPublicKeyInfo toBCSPKI(SubjectPublicKeyInfo spki) throws IOException {
        return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(fromSubjectPublicKeyInfo(spki));
    }

    /**
     * Get the qTESLA security category from a (qTESLA) AlgID
     *
     * @param algId the algorithm identifier
     * @return the security category
     */
    public static int getSecurityCategory(AlgorithmIdentifier algId) {
        switch (algId.getAlgorithm().getId()) {
            case OID_HEURISTIC_I:
                return QTESLASecurityCategory.HEURISTIC_I;
            case OID_HEURISTIC_III_SIZE:
                return QTESLASecurityCategory.HEURISTIC_III_SIZE;
            case OID_HEURISTIC_III_SPEED:
                return QTESLASecurityCategory.HEURISTIC_III_SPEED;
            case OID_PROVABLY_SECURE_I:
                return QTESLASecurityCategory.PROVABLY_SECURE_I;
            case OID_PROVABLY_SECURE_III:
                return QTESLASecurityCategory.PROVABLY_SECURE_III;
            default:
                return -1;
        }
    }

    /**
     * Get the algorithm identifier for a qTESLA security category
     *
     * @param securityCategory the security category
     * @return the OID of the algorithm identifier as string
     */
    private static String getOID(int securityCategory) {
        switch (securityCategory) {
            case QTESLASecurityCategory.HEURISTIC_I:
                return OID_HEURISTIC_I;
            case QTESLASecurityCategory.HEURISTIC_III_SIZE:
                return OID_HEURISTIC_III_SIZE;
            case QTESLASecurityCategory.HEURISTIC_III_SPEED:
                return OID_HEURISTIC_III_SPEED;
            case QTESLASecurityCategory.PROVABLY_SECURE_I:
                return OID_PROVABLY_SECURE_I;
            case QTESLASecurityCategory.PROVABLY_SECURE_III:
                return OID_PROVABLY_SECURE_III;
            default:
                return "";
        }
    }

    /**
     * Get the algorithm identifier for a qTESLA security category
     *
     * @param securityCategory the security category
     * @return the algorithm identifier
     */
    public static AlgorithmIdentifier getAlgorithmIdentifier(int securityCategory) {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(getOID(securityCategory)));
    }

}
