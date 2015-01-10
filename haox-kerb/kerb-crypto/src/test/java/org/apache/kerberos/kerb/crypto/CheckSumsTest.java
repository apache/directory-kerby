package org.apache.kerberos.kerb.crypto;

import org.apache.kerberos.kerb.spec.common.CheckSum;
import org.apache.kerberos.kerb.spec.common.CheckSumType;
import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerberos.kerb.spec.common.KeyUsage;
import org.junit.Test;

/**
 * These are to test the checksums of good answers, and the checksums
 * are deterministic. For other cases, look at CheckSumTest.
 */
public class CheckSumsTest {

    static class CksumTest {
        String plainText;
        CheckSumType cksumType;
        EncryptionType encType;
        String key;
        int keyUsage;
        String answer;

        CksumTest(String plainText, CheckSumType cksumType, EncryptionType encType,
                  int keyUsage, String key, String answer) {
            this.plainText = plainText;
            this.cksumType = cksumType;
            this.encType = encType;
            this.key = key;
            this.keyUsage = keyUsage;
            this.answer = answer;
        }
    }

    static CksumTest[] testCases = new CksumTest[] {
            new CksumTest(
                    "abc",
                    CheckSumType.CRC32, EncryptionType.NONE, 0, "",
                    "D09865CA"
            ),
            new CksumTest(
                    "one",
                    CheckSumType.RSA_MD4, EncryptionType.NONE, 0, "",
                    "305DCC2C0FDD5339969552C7B8996348"
            ),
            new CksumTest(
                    "two three four five",
                    CheckSumType.RSA_MD5, EncryptionType.NONE, 0, "",
                    "BAB5321551E1084490869635B3C26815"
            ),
            new CksumTest(
                    "",
                    CheckSumType.NIST_SHA, EncryptionType.NONE, 0, "",
                    "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
            ),
            new CksumTest(
                    "six seven",
                    CheckSumType.HMAC_SHA1_DES3, EncryptionType.DES3_CBC_SHA1, 2,
                    "7A25DF8992296DCEDA0E135BC4046E2375B3C14C98FBC162",
                    "0EEFC9C3E049AABC1BA5C401677D9AB699082BB4"
            ),
            new CksumTest(
                    "eight nine ten eleven twelve thirteen",
                    CheckSumType.HMAC_SHA1_96_AES128, EncryptionType.AES128_CTS_HMAC_SHA1_96, 3,
                    "9062430C8CDA3388922E6D6A509F5B7A",
                    "01A4B088D45628F6946614E3"
            ),
            new CksumTest(
                    "fourteen",
                    CheckSumType.HMAC_SHA1_96_AES256, EncryptionType.AES256_CTS_HMAC_SHA1_96, 4,
                    "B1AE4CD8462AFF1677053CC9279AAC30B796FB81CE21474DD3DDBCFEA4EC76D7",
                    "E08739E3279E2903EC8E3836"
            ),
            new CksumTest(
                    "fifteen sixteen",
                    CheckSumType.MD5_HMAC_ARCFOUR, EncryptionType.ARCFOUR_HMAC, 5,
                    "F7D3A155AF5E238A0B7A871A96BA2AB2",
                    "9F41DF304907DE735447001FD2A197B9"
            ),
            new CksumTest(
                    "seventeen eighteen nineteen twenty",
                    CheckSumType.HMAC_MD5_ARCFOUR, EncryptionType.ARCFOUR_HMAC, 6,
                    "F7D3A155AF5E238A0B7A871A96BA2AB2",
                    "EB38CC97E2230F59DA4117DC5859D7EC"
            ),
            new CksumTest(
                    "abcdefghijk",
                    CheckSumType.CMAC_CAMELLIA128, EncryptionType.CAMELLIA128_CTS_CMAC, 7,
                    "1DC46A8D763F4F93742BCBA3387576C3",
                    "1178E6C5C47A8C1AE0C4B9C7D4EB7B6B"
            ),
            new CksumTest(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    CheckSumType.CMAC_CAMELLIA128, EncryptionType.CAMELLIA128_CTS_CMAC, 8,
                    "5027BC231D0F3A9D23333F1CA6FDBE7C",
                    "D1B34F7004A731F23A0C00BF6C3F753A"
            ),
            new CksumTest(
                    "123456789",
                    CheckSumType.CMAC_CAMELLIA256, EncryptionType.CAMELLIA256_CTS_CMAC, 9,
                    "B61C86CC4E5D2757545AD423399FB7031ECAB913CBB900BD7A3C6DD8BF92015B",
                    "87A12CFD2B96214810F01C826E7744B1"
            ),
            new CksumTest(
                    "!@#$%^&*()!@#$%^&*()!@#$%^&*()",
                    CheckSumType.CMAC_CAMELLIA256, EncryptionType.CAMELLIA256_CTS_CMAC, 10,
                    "32164C5B434D1D1538E4CFD9BE8040FE8C4AC7ACC4B93D3314D2133668147A05",
                    "3FA0B42355E52B189187294AA252AB64"
            )
    };

    @Test
    public void testCheckSums() {
        for (CksumTest tc : testCases) {
            System.err.println("Checksum testing for " + tc.cksumType.getName());
            try {
                testWith(tc);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void testWith(CksumTest testCase) throws Exception {
        byte[] answer = TestUtil.hex2bytes(testCase.answer);
        byte[] plainData = testCase.plainText.getBytes();
        CheckSum newCksum;

        if (! CheckSumHandler.isImplemented(testCase.cksumType)) {
            System.err.println("Checksum type not supported yet: "
                    + testCase.cksumType.getName());
            return;
        }

        if (testCase.encType != EncryptionType.NONE) {
            if (! EncryptionHandler.isImplemented(testCase.encType)) {
                System.err.println("Key type not supported yet: " + testCase.encType.getName());
                return;
            }

            byte[] key = TestUtil.hex2bytes(testCase.key);
            KeyUsage keyUsage = KeyUsage.fromValue(testCase.keyUsage);
            newCksum = CheckSumHandler.checksumWithKey(testCase.cksumType, plainData, key, keyUsage);
            if (CheckSumHandler.verifyWithKey(newCksum, plainData, key, keyUsage)) {
                System.err.println("Checksum test OK for " + testCase.cksumType.getName());
            } else {
                System.err.println("Checksum test failed for " + testCase.cksumType.getName());
            }
        } else {
            newCksum = CheckSumHandler.checksum(testCase.cksumType, plainData);
            if (CheckSumHandler.verify(newCksum, plainData)) {
                System.err.println("Checksum and verifying OK for " + testCase.cksumType.getName());
            } else {
                System.err.println("Checksum and verifying failed for " + testCase.cksumType.getName());
            }
        }

        if (! newCksum.isEqual(answer)) {
            System.err.println("Checksum test failed for " + testCase.cksumType.getName());
        } else {
            System.err.println("Checksum test OK for " + testCase.cksumType.getName());
        }
    }
}
