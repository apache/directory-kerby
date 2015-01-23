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
package org.apache.kerby.kerberos.kerb.crypto;

import org.apache.kerby.kerberos.kerb.crypto.enc.provider.*;
import org.apache.kerby.kerberos.kerb.crypto.key.AesKeyMaker;
import org.apache.kerby.kerberos.kerb.crypto.key.CamelliaKeyMaker;
import org.apache.kerby.kerberos.kerb.crypto.key.Des3KeyMaker;
import org.apache.kerby.kerberos.kerb.crypto.key.DkKeyMaker;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.util.HexUtil;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * Key derivation test with known values.
 */
public class KeyDeriveTest {

    static class TestCase {
        EncryptionType encType;
        String inkey;
        String constant;
        String answer;

        TestCase(EncryptionType encType, String inkey,
                 String constant, String answer) {
            this.encType = encType;
            this.inkey = inkey;
            this.constant = constant;
            this.answer = answer;
        }
    }

    static TestCase[] testCases = new TestCase[] {
    /* Kc, Ke, Kei for a DES3 key */
            new TestCase(
                    EncryptionType.DES3_CBC_SHA1,
                    "850BB51358548CD05E86768C313E3BFE" +
                            "F7511937DCF72C3E",
                    "0000000299",
                    "F78C496D16E6C2DAE0E0B6C24057A84C" +
                            "0426AEEF26FD6DCE"
            ),
            new TestCase(
                    EncryptionType.DES3_CBC_SHA1,
                    "850BB51358548CD05E86768C313E3BFE" +
                            "F7511937DCF72C3E",
                    "00000002AA",
                    "5B5723D0B634CB684C3EBA5264E9A70D" +
                            "52E683231AD3C4CE"
            ),
            new TestCase(
                    EncryptionType.DES3_CBC_SHA1,
                    "850BB51358548CD05E86768C313E3BFE" +
                            "F7511937DCF72C3E",
                    "0000000255",
                    "A77C94980E9B7345A81525C423A737CE" +
                            "67F4CD91B6B3DA45"
            ),

    /* Kc, Ke, Ki for an AES-128 key */
            new TestCase(
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "42263C6E89F4FC28B8DF68EE09799F15",
                    "0000000299",
                    "34280A382BC92769B2DA2F9EF066854B"
            ),
            new TestCase(
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "42263C6E89F4FC28B8DF68EE09799F15",
                    "00000002AA",
                    "5B14FC4E250E14DDF9DCCF1AF6674F53"
            ),
            new TestCase(
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "42263C6E89F4FC28B8DF68EE09799F15",
                    "0000000255",
                    "4ED31063621684F09AE8D89991AF3E8F"
            ),

    /* Kc, Ke, Ki for an AES-256 key */
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "FE697B52BC0D3CE14432BA036A92E65B" +
                            "BB52280990A2FA27883998D72AF30161",
                    "0000000299",
                    "BFAB388BDCB238E9F9C98D6A878304F0" +
                            "4D30C82556375AC507A7A852790F4674"
            ),
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "FE697B52BC0D3CE14432BA036A92E65B" +
                            "BB52280990A2FA27883998D72AF30161",
                    "00000002AA",
                    "C7CFD9CD75FE793A586A542D87E0D139" +
                            "6F1134A104BB1A9190B8C90ADA3DDF37"
            ),
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "FE697B52BC0D3CE14432BA036A92E65B" +
                            "BB52280990A2FA27883998D72AF30161",
                    "0000000255",
                    "97151B4C76945063E2EB0529DC067D97" +
                            "D7BBA90776D8126D91F34F3101AEA8BA"
            ),

    /* Kc, Ke, Ki for a Camellia-128 key */
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "57D0297298FFD9D35DE5A47FB4BDE24B",
                    "0000000299",
                    "D155775A209D05F02B38D42A389E5A56"
            ),
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "57D0297298FFD9D35DE5A47FB4BDE24B",
                    "00000002AA",
                    "64DF83F85A532F17577D8C37035796AB"
            ),
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "57D0297298FFD9D35DE5A47FB4BDE24B",
                    "0000000255",
                    "3E4FBDF30FB8259C425CB6C96F1F4635"
            ),

    /* Kc, Ke, Ki for a Camellia-256 key */
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "B9D6828B2056B7BE656D88A123B1FAC6" +
                            "8214AC2B727ECF5F69AFE0C4DF2A6D2C",
                    "0000000299",
                    "E467F9A9552BC7D3155A6220AF9C1922" +
                            "0EEED4FF78B0D1E6A1544991461A9E50"
            ),
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "B9D6828B2056B7BE656D88A123B1FAC6" +
                            "8214AC2B727ECF5F69AFE0C4DF2A6D2C",
                    "00000002AA",
                    "412AEFC362A7285FC3966C6A5181E760" +
                            "5AE675235B6D549FBFC9AB6630A4C604"
            ),
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "B9D6828B2056B7BE656D88A123B1FAC6" +
                            "8214AC2B727ECF5F69AFE0C4DF2A6D2C",
                    "0000000255",
                    "FA624FA0E523993FA388AEFDC67E67EB" +
                            "CD8C08E8A0246B1D73B0D1DD9FC582B0"
            )
    };

    static DkKeyMaker getKeyMaker(EncryptionType encType) {
        switch (encType) {
            case DES3_CBC_SHA1:
                return new Des3KeyMaker(new Des3Provider());
            case AES128_CTS_HMAC_SHA1_96:
                return new AesKeyMaker(new Aes128Provider());
            case AES256_CTS_HMAC_SHA1_96:
                return new AesKeyMaker(new Aes256Provider());
            case CAMELLIA128_CTS_CMAC:
                return new CamelliaKeyMaker(new Camellia128Provider());
            case CAMELLIA256_CTS_CMAC:
                return new CamelliaKeyMaker(new Camellia256Provider());
            default:
                return null;
        }
    }

    @Test
    public void testDeriveKeys() {
        boolean overallResult = true;

        for (TestCase tc : testCases) {
            System.err.println("Key deriving test for " + tc.encType.getName());
            try {
                if (! testWith(tc)) {
                    overallResult = false;
                }
            } catch (Exception e) {
                e.printStackTrace();
                overallResult = false;
            }
        }

        if (!overallResult) {
            Assert.fail();
        }
    }

    private boolean testWith(TestCase testCase) throws Exception {
        byte[] answer = HexUtil.hex2bytes(testCase.answer);
        byte[] inkey = HexUtil.hex2bytes(testCase.inkey);
        byte[] constant = HexUtil.hex2bytes(testCase.constant);
        byte[] outkey;

        DkKeyMaker km = getKeyMaker(testCase.encType);
        outkey = km.dk(inkey, constant);
        if (! Arrays.equals(answer, outkey)) {
            System.err.println("failed with:");
            System.err.println("outKey:" + HexUtil.bytesToHex(outkey));
            System.err.println("answer:" + testCase.answer);
            return false;
        }
        return true;
    }
}
