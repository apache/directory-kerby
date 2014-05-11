package org.haox.kerb.common.crypto.encryption;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class KerberosKeyFactory
{
    public static final Map<EncryptionType, String> DEFAULT_CIPHERS;

    static {
        Map<EncryptionType, String> map = new HashMap<EncryptionType, String>();

        map.put(EncryptionType.DES_CBC_MD5, "DES");
        map.put(EncryptionType.DES3_CBC_SHA1_KD, "DESede");
        map.put(EncryptionType.RC4_HMAC, "ArcFourHmac");
        map.put(EncryptionType.AES128_CTS_HMAC_SHA1_96, "AES128");
        map.put(EncryptionType.AES256_CTS_HMAC_SHA1_96, "AES256");

        DEFAULT_CIPHERS = Collections.unmodifiableMap(map);
    }

    public static Map<EncryptionType, EncryptionKey> getKerberosKeys(String principalName,
                                                                     String passPhrase) throws KrbException {
        return getKerberosKeys(principalName, passPhrase, DEFAULT_CIPHERS.keySet());
    }

    public static Map<EncryptionType, EncryptionKey> getKerberosKeys(String principalName, String passPhrase,
        Set<EncryptionType> ciphers) throws KrbException {
        Map<EncryptionType, EncryptionKey> kerberosKeys = new HashMap<EncryptionType, EncryptionKey>();

        for (EncryptionType encryptionType : ciphers) {
            try {
                kerberosKeys.put(encryptionType, string2Key(principalName, passPhrase, encryptionType));
            } catch (IllegalArgumentException iae) {
                // Algorithm AES256 not enabled by policy.
                // Algorithm ArcFourHmac not supported by IBM JREs.
                // Algorithm DESede not supported by IBM JREs.
            }
        }

        return kerberosKeys;
    }

    public static EncryptionKey string2Key(String principalName, String passPhrase,
                                           EncryptionType encryptionType) throws KrbException {
        KerberosPrincipal principal = new KerberosPrincipal(principalName);
        KerberosKey kerberosKey = new KerberosKey(principal, passPhrase.toCharArray(),
                EncryptionUtil.getAlgoNameFromEncType(encryptionType));
        EncryptionKey ekey = new EncryptionKey();
        ekey.setKeyType(encryptionType);
        ekey.setKeyData(kerberosKey.getEncoded());

        return ekey;
    }
}
