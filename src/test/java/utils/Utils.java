package utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.*;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Utils {

    public static AsymmetricCipherKeyPair createRSAKeyPair() {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), new SecureRandom(), 4096, 25));
        return gen.generateKeyPair();
    }

    public static AsymmetricCipherKeyPair createQTESLAKeyPair(int securityCategory) {
        QTESLAKeyPairGenerator gen = new QTESLAKeyPairGenerator();
        try {
            gen.init(new QTESLAKeyGenerationParameters(securityCategory, SecureRandom.getInstanceStrong()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return gen.generateKeyPair();
    }

    public static AsymmetricCipherKeyPair createXMSSKeyPair() {
        XMSSKeyPairGenerator gen = new XMSSKeyPairGenerator();
        try {
            gen.init(new XMSSKeyGenerationParameters(new XMSSParameters(10, new SHA512Digest()), SecureRandom.getInstanceStrong()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return gen.generateKeyPair();
    }
}
