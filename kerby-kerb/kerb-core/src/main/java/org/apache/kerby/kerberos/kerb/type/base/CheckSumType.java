/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.type.base;

import org.apache.kerby.asn1.EnumType;

/**
 * The various Checksum types.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum CheckSumType implements EnumType {
    NONE                (0, "none", "None checksum type"),

    /** Defined in RFC 3961, section 6.1.3 */
    CRC32               (0x0001, "crc32", "CRC-32"),

    /** Defined in RFC 3961, section 6.1.2 */
    RSA_MD4             (0x0002, "md4", "RSA-MD4"),

    /** Defined in RFC 3961, section 6.2.5 */
    RSA_MD4_DES         (0x0003, "md4-des", "RSA-MD4 with DES cbc mode"),

    DES_CBC             (0x0004, "des-cbc", "DES cbc mode"),

    /** Defined in RFC 3961, section 6.2.7 */
    DES_MAC             (0x0004, "des-mac", "DES cbc mode"),

    //des-mac-k

    //rsa-md4-des-k

    /** Defined in RFC 3961, section 6.1.1 */
    RSA_MD5             (0x0007, "md5", "RSA-MD5"),

    /** Defined in RFC 3961, section 6.2.4 */
    RSA_MD5_DES         (0x0008, "md5-des", "RSA-MD5 with DES cbc mode"),

    NIST_SHA            (0x0009, "sha", "NIST-SHA"),

    /** Defined in RFC 3961, section 6.3 */
    HMAC_SHA1_DES3      (0x000c, "hmac-sha1-des3", "HMAC-SHA1 DES3 key"),
    HMAC_SHA1_DES3_KD   (0x000c, "hmac-sha1-des3-kd", "HMAC-SHA1 DES3 key"),

    ////RFC 3962. Used with ENCTYPE_AES128_CTS_HMAC_SHA1_96
    /** Defined in RFC 3962, section 7 */
    HMAC_SHA1_96_AES128 (0x000f, "hmac-sha1-96-aes128", "HMAC-SHA1 AES128 key"),

    //RFC 3962. Used with ENCTYPE_AES256_CTS_HMAC_SHA1_96
    /** Defined in RFC 3962, section 7 */
    HMAC_SHA1_96_AES256 (0x0010, "hmac-sha1-96-aes256", "HMAC-SHA1 AES256 key"),

    /** Defined in RFC 6803, section 9 */
    CMAC_CAMELLIA128    (0x0011, "cmac-camellia128", "CMAC Camellia128 key"),

    /** Defined in RFC 6803, section 9 */
    CMAC_CAMELLIA256    (0x0012, "cmac-camellia256", "CMAC Camellia256 key"),

    //Microsoft netlogon cksumtype
    MD5_HMAC_ARCFOUR    (-137, "md5-hmac-rc4", "Microsoft MD5 HMAC"),

    //Microsoft md5 hmac cksumtype
    /** Defined in RFC 4757, section 4 */
    HMAC_MD5_ARCFOUR    (-138, "hmac-md5-arcfour", "Microsoft HMAC MD5"),
    HMAC_MD5_ENC        (-138, "hmac-md5-enc", "Microsoft HMAC MD5"),
    HMAC_MD5_RC4        (-138, "hmac-md5-rc4", "Microsoft HMAC MD5");

    /** The inner value */
    private final int value;

    /** The CheckSum name */
    private final String name;

    /** The CheckSum description */
    private final String displayName;

    /**
     * Create a new enum instance
     */
    CheckSumType(int value, String name, String displayName) {
        this.value = value;
        this.name = name;
        this.displayName = displayName;
    }

    /**
     * Get the CheckSumType associated with a value.
     * 
     * @param value The integer value of the CheckSumType we are looking for
     * @return The associated CheckSumType, or NONE if not found or if value is null
     */
    public static CheckSumType fromValue(Integer value) {
        if (value != null) {
            for (EnumType e : values()) {
                if (e.getValue() == value) {
                    return (CheckSumType) e;
                }
            }
        }
        return NONE;
    }

    /**
     * Get the CheckSumType associated with a name.
     * 
     * @param name The name of the CheckSumType we are looking for
     * @return The associated CheckSumType, or NONE if not found or if name is null
     */
    public static CheckSumType fromName(String name) {
        if (name != null) {
            for (CheckSumType cs : values()) {
                if (cs.getName().equals(name)) {
                    return cs;
                }
            }
        }
        return NONE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {
        return name;
    }

    /**
     * @return The CheckSum description
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Is the type uses AES256 or not
     * 
     * @return <tt>true</tt> if uses AES256, <tt>false</tt> otherwise.
     */
    public boolean usesAES256() {
        return name.contains("aes256");
    }
}
