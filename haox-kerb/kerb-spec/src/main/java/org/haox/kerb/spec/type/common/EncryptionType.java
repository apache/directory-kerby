package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbEnum;
import org.haox.kerb.spec.type.KrbInteger;

public enum EncryptionType implements KrbEnum {
    /**
     * The "unknown" encryption type.
     */
    UNKNOWN(-1, "UNKNOWN"),

    /**
     * The "null" encryption type.
     */
    NULL(0, "null"),

    /**
     * The des-cbc-crc encryption type.
     */
    DES_CBC_CRC(1, "des-cbc-crc"),

    /**
     * The des-cbc-md4 encryption type.
     */
    DES_CBC_MD4(2, "des-cbc-md4"),

    /**
     * The des-cbc-md5 encryption type.
     */
    DES_CBC_MD5(3, "des-cbc-md5"),

    /**
     * The reserved (4) encryption type.
     */
    RESERVED4(4, "[reserved]"),

    /**
     * The des3-cbc-md5 encryption type.
     */
    DES3_CBC_MD5(5, "des3-cbc-md5"),

    /**
     * The reserved (6) encryption type.
     */
    RESERVED6(6, "[reserved]"),

    /**
     * The des3-cbc-sha1 encryption type.
     */
    DES3_CBC_SHA1(7, "des3-cbc-sha1"),

    /**
     * The dsaWithSHA1-CmsOID encryption type.
     */
    DSAWITHSHA1_CMSOID(9, "dsaWithSHA1-CmsOID"),

    /**
     * The md5WithRSAEncryption-CmsOID encryption type.
     */
    MD5WITHRSAENCRYPTION_CMSOID(10, "md5WithRSAEncryption-CmsOID"),

    /**
     * The sha1WithRSAEncryption-CmsOID encryption type.
     */
    SHA1WITHRSAENCRYPTION_CMSOID(11, "sha1WithRSAEncryption-CmsOID"),

    /**
     * The rc2CBC-EnvOID encryption type.
     */
    RC2CBC_ENVOID(12, "rc2CBC-EnvOID"),

    /**
     * The rsaEncryption-EnvOID encryption type.
     */
    RSAENCRYPTION_ENVOID(13, "rsaEncryption-EnvOID"),

    /**
     * The rsaES-OAEP-ENV-OID encryption type.
     */
    RSAES_OAEP_ENV_OID(14, "rsaES-OAEP-ENV-OID"),

    /**
     * The des-ede3-cbc-Env-OID encryption type.
     */
    DES_EDE3_CBC_ENV_OID(15, "des-ede3-cbc-Env-OID"),

    /**
     * The des3-cbc-sha1-kd encryption type.
     */
    DES3_CBC_SHA1_KD(16, "des3-cbc-sha1-kd"),

    /**
     * The aes128-cts-hmac-sha1-96 encryption type.
     */
    AES128_CTS_HMAC_SHA1_96(17, "aes128-cts-hmac-sha1-96"),

    /**
     * The aes256-cts-hmac-sha1-96 encryption type.
     */
    AES256_CTS_HMAC_SHA1_96(18, "aes256-cts-hmac-sha1-96"),

    /**
     * The rc4-hmac encryption type.
     */
    RC4_HMAC(23, "rc4-hmac"),

    /**
     * The rc4-hmac-exp encryption type.
     */
    RC4_HMAC_EXP(24, "rc4-hmac-exp"),

    /**
     * The subkey-keymaterial encryption type.
     */
    SUBKEY_KEYMATERIAL(65, "subkey-keymaterial"),

    /**
     * The rc4-md4 encryption type.
     */
    RC4_MD4(-128, "rc4-md4"),

    /**
     * The c4-hmac-old encryption type.
     */
    RC4_HMAC_OLD(-133, "rc4-hmac-old"),

    /**
     * The rc4-hmac-old-exp encryption type.
     */
    RC4_HMAC_OLD_EXP(-135, "rc4-hmac-old-exp");

    /**
     * The value/code for the encryption type.
     */
    private final int value;

    /**
     * The name
     */
    private final String name;

    private EncryptionType(int value, String name) {
        this.value = value;
        this.name = name;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static EncryptionType fromValue(KrbInteger value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.getValue().intValue()) {
                    return (EncryptionType) e;
                }
            }
        }

        return UNKNOWN;
    }

}
