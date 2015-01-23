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

/**
 * According to krb5.hin
 */
public enum EncryptionType implements KrbEnum {

    NONE(0, "none", "None encryption type"),

    DES_CBC_CRC(0x0001, "des-cbc-crc", "DES cbc mode with CRC-32"),

    DES_CBC_MD4(0x0002, "des-cbc-md4", "DES cbc mode with RSA-MD4"),

    DES_CBC_MD5(0x0003, "des-cbc-md5", "DES cbc mode with RSA-MD5"),
    DES(0x0003, "des", "DES cbc mode with RSA-MD5"),

    DES_CBC_RAW(0x0004, "des-cbc-raw", "DES cbc mode raw"),

    DES3_CBC_SHA(0x0005, "des3-cbc-sha", "DES-3 cbc with SHA1"),

    DES3_CBC_RAW(0x0006, "des3-cbc-raw", "Triple DES cbc mode raw"),

    DES_HMAC_SHA1(0x0008, "des-hmac-sha1", "DES with HMAC/sha1"),

    DSA_SHA1_CMS(0x0009, "dsa-sha1-cms", "DSA with SHA1, CMS signature"),

    MD5_RSA_CMS(0x000a, "md5-rsa-cms", "MD5 with RSA, CMS signature"),

    SHA1_RSA_CMS(0x000b, "sha1-rsa-cms", "SHA1 with RSA, CMS signature"),

    RC2_CBC_ENV(0x000c, "rc2-cbc-env", "RC2 cbc mode, CMS enveloped data"),

    RSA_ENV(0x000d, "rsa-env", "RSA encryption, CMS enveloped data"),

    RSA_ES_OAEP_ENV(0x000e, "rsa-es-oaep-env", "RSA w/OEAP encryption, CMS enveloped data"),

    DES3_CBC_ENV(0x000f, "des3-cbc-env", "DES-3 cbc mode, CMS enveloped data"),

    DES3_CBC_SHA1(0x0010, "des3-cbc-sha1", "Triple DES cbc mode with HMAC/sha1"),
    DES3_HMAC_SHA1(0x0010, "des3-hmac-sha1", "Triple DES cbc mode with HMAC/sha1"),
    DES3_CBC_SHA1_KD(0x0010, "des3-cbc-sha1-kd", "Triple DES cbc mode with HMAC/sha1"),

    AES128_CTS_HMAC_SHA1_96 (0x0011, "aes128-cts-hmac-sha1-96", "AES-128 CTS mode with 96-bit SHA-1 HMAC"),
    AES128_CTS (0x0011, "aes128-cts", "AES-128 CTS mode with 96-bit SHA-1 HMAC"),

    AES256_CTS_HMAC_SHA1_96(0x0012, "aes256-cts-hmac-sha1-96", "AES-256 CTS mode with 96-bit SHA-1 HMAC"),
    AES256_CTS(0x0012, "aes256-cts", "AES-256 CTS mode with 96-bit SHA-1 HMAC"),

    ARCFOUR_HMAC(0x0017, "arcfour-hmac", "ArcFour with HMAC/md5"),
    RC4_HMAC(0x0017, "rc4-hmac", "ArcFour with HMAC/md5"),
    ARCFOUR_HMAC_MD5(0x0017, "arcfour-hmac-md5", "ArcFour with HMAC/md5"),

    ARCFOUR_HMAC_EXP(0x0018, "arcfour-hmac-exp", "Exportable ArcFour with HMAC/md5"),
    RC4_HMAC_EXP(0x0018, "rc4-hmac-exp", "Exportable ArcFour with HMAC/md5"),
    ARCFOUR_HMAC_MD5_EXP(0x0018, "arcfour-hmac-md5-exp", "Exportable ArcFour with HMAC/md5"),

    CAMELLIA128_CTS_CMAC(0x0019, "camellia128-cts-cmac", "Camellia-128 CTS mode with CMAC"),
    CAMELLIA128_CTS(0x0019, "camellia128-cts", "Camellia-128 CTS mode with CMAC"),

    CAMELLIA256_CTS_CMAC(0x001a, "camellia256-cts-cmac", "Camellia-256 CTS mode with CMAC"),
    CAMELLIA256_CTS(0x001a, "camellia256-cts", "Camellia-256 CTS mode with CMAC");

    //UNKNOWN(0x01ff, "UNKNOWN", "Unknown encryption type");

    private final int value;

    private final String name;

    private final String displayName;

    private EncryptionType(int value, String name, String displayName) {
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

    public static EncryptionType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value) {
                    return (EncryptionType) e;
                }
            }
        }
        return NONE;
    }

    public static EncryptionType fromName(String name) {
        if (name != null) {
            for (EncryptionType e : values()) {
                if (e.getName().equals(name)) {
                    return (EncryptionType) e;
                }
            }
        }
        return NONE;
    }
}
