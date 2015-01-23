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
package org.apache.kerby.kerberos.kerb.spec.common;

import org.apache.kerby.kerberos.kerb.spec.KrbEnum;

public enum CheckSumType implements KrbEnum {
    NONE(0, "none", "None checksum type"),

    CRC32(0x0001, "crc32", "CRC-32"),

    RSA_MD4(0x0002, "md4", "RSA-MD4"),

    RSA_MD4_DES(0x0003, "md4-des", "RSA-MD4 with DES cbc mode"),

    DES_CBC(0x0004, "des-cbc", "DES cbc mode"),
    DES_MAC(0x0004, "des-mac", "DES cbc mode"),

    //des-mac-k

    //rsa-md4-des-k

    RSA_MD5(0x0007, "md5", "RSA-MD5"),

    RSA_MD5_DES(0x0008, "md5-des", "RSA-MD5 with DES cbc mode"),

    NIST_SHA(0x0009, "sha", "NIST-SHA"),

    HMAC_SHA1_DES3(0x000c, "hmac-sha1-des3", "HMAC-SHA1 DES3 key"),
    HMAC_SHA1_DES3_KD(0x000c, "hmac-sha1-des3-kd", "HMAC-SHA1 DES3 key"),

    ////RFC 3962. Used with ENCTYPE_AES128_CTS_HMAC_SHA1_96
    HMAC_SHA1_96_AES128(0x000f, "hmac-sha1-96-aes128", "HMAC-SHA1 AES128 key"),

    //RFC 3962. Used with ENCTYPE_AES256_CTS_HMAC_SHA1_96
    HMAC_SHA1_96_AES256(0x0010, "hmac-sha1-96-aes256", "HMAC-SHA1 AES256 key"),

    //RFC 6803
    CMAC_CAMELLIA128(0x0011, "cmac-camellia128", "CMAC Camellia128 key"),

    //RFC 6803
    CMAC_CAMELLIA256(0x0012, "cmac-camellia256", "CMAC Camellia256 key"),

    //Microsoft netlogon cksumtype
    MD5_HMAC_ARCFOUR(-137, "md5-hmac-rc4", "Microsoft MD5 HMAC"),

    //Microsoft md5 hmac cksumtype
    HMAC_MD5_ARCFOUR(-138, "hmac-md5-arcfour", "Microsoft HMAC MD5"),
    HMAC_MD5_ENC(-138, "hmac-md5-enc", "Microsoft HMAC MD5"),
    HMAC_MD5_RC4(-138, "hmac-md5-rc4", "Microsoft HMAC MD5");

    private final int value;

    private final String name;

    private final String displayName;

    private CheckSumType(int value, String name, String displayName) {
        this.value = value;
        this.name = name;
        this.displayName = displayName;
    }

    @Override
    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static CheckSumType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value) {
                    return (CheckSumType) e;
                }
            }
        }
        return NONE;
    }

    public static CheckSumType fromName(String name) {
        if (name != null) {
            for (CheckSumType cs : values()) {
                if (cs.getName() == name) {
                    return (CheckSumType) cs;
                }
            }
        }
        return NONE;
    }
}
