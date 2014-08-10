package org.haox.kerb;

import org.haox.kerb.crypto.CheckSumHandler;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSum;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.junit.Test;

public class CheckSumTest {

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
                    "0xD0 98 65 CA"
            ),
            new CksumTest(
                    "one",
                    CheckSumType.RSA_MD4, EncryptionType.NONE, 0, "",
                    "0x30 5D CC 2C 0F DD 53 39 96 95 52 C7 B8 99 63 48"
            ),
            new CksumTest(
                    "two three four five",
                    CheckSumType.RSA_MD5, EncryptionType.NONE, 0, "",
                    "0xBA B5 32 15 51 E1 08 44 90 86 96 35 B3 C2 68 15"
            ),
            new CksumTest(
                    "",
                    CheckSumType.NIST_SHA, EncryptionType.NONE, 0, "",
                    "0xDA 39 A3 EE 5E 6B 4B 0D 32 55 BF EF 95 60 18 90 AF D8 07 09"
            ),
            new CksumTest(
                    "six seven",
                    CheckSumType.HMAC_SHA1_DES3, EncryptionType.DES3_CBC_SHA1, 2,
                    "0x7A 25 DF 89 92 29 6D CE DA 0E 13 5B C4 04 6E 23 75 B3 C1 4C 98 FB C1 62",
                    "0x0E EF C9 C3 E0 49 AA BC 1B A5 C4 01 67 7D 9A B6 99 08 2B B4"
            ),
            new CksumTest(
                    "eight nine ten eleven twelve thirteen",
                    CheckSumType.HMAC_SHA1_96_AES128, EncryptionType.AES128_CTS_HMAC_SHA1_96, 3,
                    "0x90 62 43 0C 8C DA 33 88 92 2E 6D 6A 50 9F 5B 7A",
                    "0x01 A4 B0 88 D4 56 28 F6 94 66 14 E3"
            ),
            new CksumTest(
                    "fourteen",
                    CheckSumType.HMAC_SHA1_96_AES256, EncryptionType.AES256_CTS_HMAC_SHA1_96, 4,
                    "0xB1 AE 4C D8 46 2A FF 16 77 05 3C C9 27 9A AC 30 B7 96 FB 81 CE 21 47 4D D3 DD BC FE A4 EC 76 D7",
                    "0xE0 87 39 E3 27 9E 29 03 EC 8E 38 36"
            ),
            new CksumTest(
                    "fifteen sixteen",
                    CheckSumType.MD5_HMAC_ARCFOUR, EncryptionType.ARCFOUR_HMAC, 5,
                    "0xF7 D3 A1 55 AF 5E 23 8A 0B 7A 87 1A 96 BA 2A B2",
                    "0x9F 41 DF 30 49 07 DE 73 54 47 00 1F D2 A1 97 B9"
            ),
            new CksumTest(
                    "seventeen eighteen nineteen twenty",
                    CheckSumType.HMAC_MD5_ARCFOUR, EncryptionType.ARCFOUR_HMAC, 6,
                    "0xF7 D3 A1 55 AF 5E 23 8A 0B 7A 87 1A 96 BA 2A B2",
                    "0xEB 38 CC 97 E2 23 0F 59 DA 41 17 DC 58 59 D7 EC"
            ),
            new CksumTest(
                    "abcdefghijk",
                    CheckSumType.CMAC_CAMELLIA128, EncryptionType.CAMELLIA128_CTS_CMAC, 7,
                    "0x1D C4 6A 8D 76 3F 4F 93 74 2B CB A3 38 75 76 C3",
                    "0x11 78 E6 C5 C4 7A 8C 1A E0 C4 B9 C7 D4 EB 7B 6B"
            ),
            new CksumTest(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    CheckSumType.CMAC_CAMELLIA128, EncryptionType.CAMELLIA128_CTS_CMAC, 8,
                    "0x50 27 BC 23 1D 0F 3A 9D 23 33 3F 1C A6 FD BE 7C",
                    "0xD1 B3 4F 70 04 A7 31 F2 3A 0C 00 BF 6C 3F 75 3A"
            ),
            new CksumTest(
                    "123456789",
                    CheckSumType.CMAC_CAMELLIA256, EncryptionType.CAMELLIA256_CTS_CMAC, 9,
                    "0xB6 1C 86 CC 4E 5D 27 57 54 5A D4 23 39 9F B7 03 1E CA B9 13 CB B9 00 BD 7A 3C 6D D8 BF 92 01 5B",
                    "0x87 A1 2C FD 2B 96 21 48 10 F0 1C 82 6E 77 44 B1"
            ),
            new CksumTest(
                    "!@#$%^&*()!@#$%^&*()!@#$%^&*()",
                    CheckSumType.CMAC_CAMELLIA256, EncryptionType.CAMELLIA256_CTS_CMAC, 10,
                    "0x32 16 4C 5B 43 4D 1D 15 38 E4 CF D9 BE 80 40 FE 8C 4A C7 AC C4 B9 3D 33 14 D2 13 36 68 14 7A 05",
                    "0x3F A0 B4 23 55 E5 2B 18 91 87 29 4A A2 52 AB 64"
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
        byte[] answer = Util.hex2bytes(testCase.answer);
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

            byte[] key = Util.hex2bytes(testCase.key);
            KeyUsage keyUsage = KeyUsage.fromValue(testCase.keyUsage);
            newCksum = CheckSumHandler.checksumWithKey(testCase.cksumType, plainData, key, keyUsage);
        } else {
            newCksum = CheckSumHandler.checksum(testCase.cksumType, plainData);
        }

        if (! newCksum.isEqual(answer)) {
            System.err.println("Checksum test failed for " + testCase.cksumType.getName());
        } else {
            System.err.println("Checksum test OK for " + testCase.cksumType.getName());
        }
    }
}
