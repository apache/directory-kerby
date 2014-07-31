package org.haox.kerb.common;

import org.haox.kerb.crypto2.*;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.PrincipalName;

import java.security.GeneralSecurityException;
import java.util.*;

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
                                           EncryptionType eType) throws KrbException {
        PrincipalName principal = new PrincipalName(principalName);
        byte[] keyBytes = stringToKey(passPhrase.toCharArray(),
                getSalt(principal), null, eType);
        return new EncryptionKey(eType, keyBytes);
    }

    private static String getSalt(PrincipalName principalName) {
        StringBuffer salt = new StringBuffer();
        if (principalName.getRealm() != null) {
            salt.append(principalName.getRealm().toString());
        }
        List<String> nameStrings = principalName.getNameStrings();
        for (String ns : nameStrings) {
            salt.append(ns);
        }
        return salt.toString();
    }

    private static byte[] stringToKey(char[] password, String salt,
                                      byte[] s2kparams, EncryptionType keyType) throws KrbException {

        char[] slt = salt.toCharArray();
        char[] pwsalt = new char[password.length + slt.length];
        System.arraycopy(password, 0, pwsalt, 0, password.length);
        System.arraycopy(slt, 0, pwsalt, password.length, slt.length);
        Arrays.fill(slt, '0');

        try {
            switch (keyType) {
                case DES_CBC_CRC:
                case DES_CBC_MD5:
                    return Des.string_to_key_bytes(pwsalt);

                case DES3_CBC_SHA1:
                case DES3_CBC_SHA1_KD:
                    return Des3.stringToKey(pwsalt);

                case ARCFOUR_HMAC:
                    return ArcFourHmac.stringToKey(password);

                case AES128_CTS_HMAC_SHA1_96:
                    return Aes128.stringToKey(password, salt, s2kparams);

                case AES256_CTS_HMAC_SHA1_96:
                    return Aes256.stringToKey(password, salt, s2kparams);

                default:
                    throw new IllegalArgumentException("encryption type "
                            + keyType.name() + " not supported");
            }

        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        } finally {
            Arrays.fill(pwsalt, '0');
        }
    }
}
