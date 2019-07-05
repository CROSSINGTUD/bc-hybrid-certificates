package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.security.*;

public class RSAUtils {

    public static KeyPair toKeyPair(AsymmetricCipherKeyPair pair) {
        RSAKeyParameters pub = (RSAKeyParameters)pair.getPublic();
        RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)pair.getPrivate();
        return new KeyPair(new BCRSAPublicKey(pub), new BCRSAPrivateCrtKey(priv));
    }
}
