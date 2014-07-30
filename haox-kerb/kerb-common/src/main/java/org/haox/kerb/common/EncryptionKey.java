package org.haox.kerb.common;

import org.haox.kerb.crypto2.*;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbErrorCode;

import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * This class encapsulates the concept of an EncryptionKey. An encryption
 * key is defined in RFC 4120 as:
 *
 * EncryptionKey   ::= SEQUENCE {
 *         keytype         [0] Int32 -- actually encryption type --,
 *         keyvalue        [1] OCTET STRING
 * }
 *
 * keytype
 *     This field specifies the encryption type of the encryption key
 *     that follows in the keyvalue field.  Although its name is
 *     "keytype", it actually specifies an encryption type.  Previously,
 *     multiple cryptosystems that performed encryption differently but
 *     were capable of using keys with the same characteristics were
 *     permitted to share an assigned number to designate the type of
 *     key; this usage is now deprecated.
 *
 * keyvalue
 *     This field contains the key itself, encoded as an octet string.
 */

public class EncryptionKey
    implements Cloneable {

    public static final EncryptionKey NULL_KEY =
        new EncryptionKey(new byte[] {}, EncryptedData.ETYPE_NULL, null);

    private int keyType;
    private byte[] keyValue;
    private Integer kvno; // not part of ASN1 encoding;

    private static final boolean DEBUG = true;

    public synchronized int getEType() {
        return keyType;
    }

    public final Integer getKeyVersionNumber() {
        return kvno;
    }

    /**
     * Returns the raw key bytes, not in any ASN.1 encoding.
     */
    public final byte[] getBytes() {
        // This method cannot be called outside sun.security, hence no
        // cloning. getEncoded() calls this method.
        return keyValue;
    }

    public synchronized Object clone() {
        return new EncryptionKey(keyValue, keyType, kvno);
    }

    /**
     * Obtains a key for a given etype of a principal with possible new salt
     * and s2kparams
     * @param cname NOT null
     * @param password NOT null
     * @param etype
     * @param snp can be NULL
     * @returns never null
     */
    /*
    public static EncryptionKey acquireSecretKey(PrincipalName cname,
            char[] password, int etype, PAData.SaltAndParams snp)
            throws KrbException {
        String salt;
        byte[] s2kparams;
        if (snp != null) {
            salt = snp.salt != null ? snp.salt : cname.getSalt();
            s2kparams = snp.params;
        } else {
            salt = cname.getSalt();
            s2kparams = null;
        }
        return acquireSecretKey(password, salt, etype, s2kparams);
    }*/

    /**
     * Obtains a key for a given etype with salt and optional s2kparams
     * @param password NOT null
     * @param salt NOT null
     * @param etype
     * @param s2kparams can be NULL
     * @returns never null
     */
    public static EncryptionKey acquireSecretKey(char[] password,
            String salt, int etype, byte[] s2kparams)
            throws KrbException {

        return new EncryptionKey(
                        stringToKey(password, salt, s2kparams, etype),
                        etype, null);
    }

    /**
     * Generate a list of keys using the given principal and password.
     * Construct a key for each configured etype.
     * Caller is responsible for clearing password.
     */
    /*
     * Usually, when keyType is decoded from ASN.1 it will contain a
     * value indicating what the algorithm to be used is. However, when
     * converting from a password to a key for the AS-EXCHANGE, this
     * keyType will not be available. Use builtin list of default etypes
     * as the default in that case. If default_tkt_enctypes was set in
     * the libdefaults of krb5.conf, then use that sequence.
     */
    public static EncryptionKey[] acquireSecretKeys(char[] password,
            String salt) throws KrbException {

        int[] etypes = EType.getDefaults("default_tkt_enctypes");
        if (etypes == null) {
            etypes = EType.getBuiltInDefaults();
        }

        EncryptionKey[] encKeys = new EncryptionKey[etypes.length];
        for (int i = 0; i < etypes.length; i++) {
            if (EType.isSupported(etypes[i])) {
                encKeys[i] = new EncryptionKey(
                        stringToKey(password, salt, null, etypes[i]),
                        etypes[i], null);
            } else {
                if (DEBUG) {
                    System.out.println("Encryption Type " +
                        EType.toString(etypes[i]) +
                        " is not supported/enabled");
                }
            }
        }
        return encKeys;
    }

    // Used in Krb5AcceptCredential, self
    public EncryptionKey(byte[] keyValue,
                         int keyType,
                         Integer kvno) {

        if (keyValue != null) {
            this.keyValue = new byte[keyValue.length];
            System.arraycopy(keyValue, 0, this.keyValue, 0, keyValue.length);
        } else {
            throw new IllegalArgumentException("EncryptionKey: " +
                                               "Key bytes cannot be null!");
        }
        this.keyType = keyType;
        this.kvno = kvno;
    }

    /**
     * Constructs an EncryptionKey by using the specified key type and key
     * value.  It is used to recover the key when retrieving data from
     * credential cache file.
     *
     */
     // Used in JSSE (KerberosWrapper), Credentials,
     // javax.security.auth.kerberos.KeyImpl
    public EncryptionKey(int keyType,
                         byte[] keyValue) {
        this(keyValue, keyType, null);
    }

    private static byte[] stringToKey(char[] password, String salt,
        byte[] s2kparams, int keyType) throws KrbException {

        char[] slt = salt.toCharArray();
        char[] pwsalt = new char[password.length + slt.length];
        System.arraycopy(password, 0, pwsalt, 0, password.length);
        System.arraycopy(slt, 0, pwsalt, password.length, slt.length);
        Arrays.fill(slt, '0');

        try {
            switch (keyType) {
                case EncryptedData.ETYPE_DES_CBC_CRC:
                case EncryptedData.ETYPE_DES_CBC_MD5:
                        return Des.string_to_key_bytes(pwsalt);

                case EncryptedData.ETYPE_DES3_CBC_HMAC_SHA1_KD:
                        return Des3.stringToKey(pwsalt);

                case EncryptedData.ETYPE_ARCFOUR_HMAC:
                        return ArcFourHmac.stringToKey(password);

                case EncryptedData.ETYPE_AES128_CTS_HMAC_SHA1_96:
                        return Aes128.stringToKey(password, salt, s2kparams);

                case EncryptedData.ETYPE_AES256_CTS_HMAC_SHA1_96:
                        return Aes256.stringToKey(password, salt, s2kparams);

                default:
                        throw new IllegalArgumentException("encryption type " +
                        EType.toString(keyType) + " not supported");
            }

        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        } finally {
            Arrays.fill(pwsalt, '0');
        }
    }

    // Used in javax.security.auth.kerberos.KeyImpl
    public EncryptionKey(char[] password,
                         String salt,
                         String algorithm) throws KrbException {

        if (algorithm == null || algorithm.equalsIgnoreCase("DES")) {
            keyType = EncryptedData.ETYPE_DES_CBC_MD5;
        } else if (algorithm.equalsIgnoreCase("DESede")) {
            keyType = EncryptedData.ETYPE_DES3_CBC_HMAC_SHA1_KD;
        } else if (algorithm.equalsIgnoreCase("AES128")) {
            keyType = EncryptedData.ETYPE_AES128_CTS_HMAC_SHA1_96;
        } else if (algorithm.equalsIgnoreCase("ArcFourHmac")) {
            keyType = EncryptedData.ETYPE_ARCFOUR_HMAC;
        } else if (algorithm.equalsIgnoreCase("AES256")) {
            keyType = EncryptedData.ETYPE_AES256_CTS_HMAC_SHA1_96;
            // validate if AES256 is enabled
            if (!EType.isSupported(keyType)) {
                throw new IllegalArgumentException("Algorithm " + algorithm +
                        " not enabled");
            }
        } else {
            throw new IllegalArgumentException("Algorithm " + algorithm +
                " not supported");
        }

        keyValue = stringToKey(password, salt, null, keyType);
        kvno = null;
    }

    /**
     * Generates a sub-sessionkey from a given session key.
     */
     // Used in KrbApRep, KrbApReq
    EncryptionKey(EncryptionKey key) throws KrbException {
        // generate random sub-session key
        keyValue = Confounder.bytes(key.keyValue.length);
        for (int i = 0; i < keyValue.length; i++) {
          keyValue[i] ^= key.keyValue[i];
        }
        keyType = key.keyType;

        // check for key parity and weak keys
        try {
            // check for DES key
            if ((keyType == EncryptedData.ETYPE_DES_CBC_MD5) ||
                (keyType == EncryptedData.ETYPE_DES_CBC_CRC)) {
                // fix DES key parity
                if (!DESKeySpec.isParityAdjusted(keyValue, 0)) {
                    keyValue = Des.set_parity(keyValue);
                }
                // check for weak key
                if (DESKeySpec.isWeak(keyValue, 0)) {
                    keyValue[7] = (byte)(keyValue[7] ^ 0xF0);
                }
            }
            // check for 3DES key
            if (keyType == EncryptedData.ETYPE_DES3_CBC_HMAC_SHA1_KD) {
                // fix 3DES key parity
                if (!DESedeKeySpec.isParityAdjusted(keyValue, 0)) {
                    keyValue = Des3.parityFix(keyValue);
                }
                // check for weak keys
                byte[] oneKey = new byte[8];
                for (int i=0; i<keyValue.length; i+=8) {
                    System.arraycopy(keyValue, i, oneKey, 0, 8);
                    if (DESKeySpec.isWeak(oneKey, 0)) {
                        keyValue[i+7] = (byte)(keyValue[i+7] ^ 0xF0);
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }

    /**
     * Find a key with given etype
     */
    public static EncryptionKey findKey(int etype, EncryptionKey[] keys)
            throws KrbException {
        return findKey(etype, null, keys);
    }

    /**
     * Determines if a kvno matches another kvno. Used in the method
     * findKey(type, kvno, keys). Always returns true if either input
     * is null or zero, in case any side does not have kvno info available.
     *
     * Note: zero is included because N/A is not a legal value for kvno
     * in javax.security.auth.kerberos.KerberosKey. Therefore, the info
     * that the kvno is N/A might be lost when converting between this
     * class and KerberosKey.
     */
    private static boolean versionMatches(Integer v1, Integer v2) {
        if (v1 == null || v1 == 0 || v2 == null || v2 == 0) {
            return true;
        }
        return v1.equals(v2);
    }

    /**
     * Find a key with given etype and kvno
     * @param kvno if null, return any (first?) key
     */
    public static EncryptionKey findKey(int etype, Integer kvno, EncryptionKey[] keys)
        throws KrbException {

        // check if encryption type is supported
        if (!EType.isSupported(etype)) {
            throw new KrbException("Encryption type " +
                EType.toString(etype) + " is not supported/enabled");
        }

        int ktype;
        boolean etypeFound = false;
        for (int i = 0; i < keys.length; i++) {
            ktype = keys[i].getEType();
            if (EType.isSupported(ktype)) {
                Integer kv = keys[i].getKeyVersionNumber();
                if (etype == ktype) {
                    etypeFound = true;
                    if (versionMatches(kvno, kv)) {
                        return keys[i];
                    }
                }
            }
        }

        // Key not found.
        // allow DES key to be used for the DES etypes
        if ((etype == EncryptedData.ETYPE_DES_CBC_CRC ||
            etype == EncryptedData.ETYPE_DES_CBC_MD5)) {
            for (int i = 0; i < keys.length; i++) {
                ktype = keys[i].getEType();
                if (ktype == EncryptedData.ETYPE_DES_CBC_CRC ||
                        ktype == EncryptedData.ETYPE_DES_CBC_MD5) {
                    Integer kv = keys[i].getKeyVersionNumber();
                    etypeFound = true;
                    if (versionMatches(kvno, kv)) {
                        return new EncryptionKey(etype, keys[i].getBytes());
                    }
                }
            }
        }
        if (etypeFound) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADKEYVER);
        }
        return null;
    }
}
