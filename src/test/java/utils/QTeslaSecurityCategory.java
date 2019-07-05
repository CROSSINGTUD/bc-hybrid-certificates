package utils;

import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;

public enum QTeslaSecurityCategory {
    HEURISTIC_I(QTESLASecurityCategory.HEURISTIC_I),
    HEURISTIC_III_SPEED(QTESLASecurityCategory.HEURISTIC_III_SPEED),
    HEURISTIC_III_SIZE(QTESLASecurityCategory.HEURISTIC_III_SIZE),
    PROVABLY_SECURE_I(QTESLASecurityCategory.PROVABLY_SECURE_I),
    PROVABLY_SECURE_III(QTESLASecurityCategory.PROVABLY_SECURE_III);

    private final int value;

    QTeslaSecurityCategory(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

}
