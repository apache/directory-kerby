package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbEnum;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.KrbInteger;

import java.math.BigInteger;

public enum ChecksumType implements KrbEnum {
    NONE(-1),
    CRC32(0x0001),
    RSA_MD4(0x0002),
    RSA_MD4_DES(0x0003),
    DESCBC(0x0004),
    //des-mac-k
    //rsa-md4-des-k
    RSA_MD5(0x0007),
    RSA_MD5_DES(0x0008),
    NIST_SHA(0x0009),
    HMAC_SHA1_DES3(0x000c),
    HMAC_SHA1_96_AES128(0x000f), //RFC 3962. Used with ENCTYPE_AES128_CTS_HMAC_SHA1_96
    HMAC_SHA1_96_AES256(0x0010), //RFC 3962. Used with ENCTYPE_AES256_CTS_HMAC_SHA1_96
    CMAC_CAMELLIA128(0x0011), //RFC 6803
    CMAC_CAMELLIA256(0x0012), //RFC 6803
    MD5_HMAC_ARCFOUR(-137), //Microsoft netlogon cksumtype
    HMAC_MD5_ARCFOUR(-138); //Microsoft md5 hmac cksumtype

    private final int value;

    private ChecksumType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static ChecksumType fromValue(KrbInteger value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.getValue().intValue()) {
                    return (ChecksumType) e;
                }
            }
        }

        return NONE;
    }
}
