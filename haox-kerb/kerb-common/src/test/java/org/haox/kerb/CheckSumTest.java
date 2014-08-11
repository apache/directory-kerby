package org.haox.kerb;

import org.haox.kerb.crypto.CheckSumHandler;
import org.haox.kerb.spec.type.common.*;
import org.junit.Test;

/**
 * Only used to test for rsa-md4-des and rsa-md5-des
 */
public class CheckSumTest {

    static class CksumTest {
        CheckSumType cksumType;
        String plainText;
        String knownChecksum;

        CksumTest(CheckSumType cksumType, String plainText, String knownChecksum) {
            this.cksumType = cksumType;
            this.plainText = plainText;
            this.knownChecksum = knownChecksum;
        }
    }

    static CksumTest[] testCases = new CksumTest[] {
            new CksumTest(
                    CheckSumType.RSA_MD4_DES,
                    "this is a test",
                    "0xe3 f7 6a 07 f3 40 1e 35 36 b4 3a 3f 54 22 6c 39 42 2c 35 68 2c 35 48 35"
            ),
            new CksumTest(
                    CheckSumType.RSA_MD5_DES,
                    "this is a test",
                    "0xe3 f7 6a 07 f3 40 1e 35 11 43 ee 6f 4c 09 be 1e db 42 64 d5 50 15 db 53"
            )
    };

    static byte[] TESTKEY = { (byte)0x45, (byte)0x01, (byte)0x49, (byte)0x61, (byte)0x58,
            (byte)0x19, (byte)0x1a, (byte)0x3d };

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
        byte[] knownChecksum = Util.hex2bytes(testCase.knownChecksum);
        byte[] plainData = testCase.plainText.getBytes();
        CheckSum newCksum;

        if (! CheckSumHandler.isImplemented(testCase.cksumType)) {
            System.err.println("Checksum type not supported yet: "
                    + testCase.cksumType.getName());
            return;
        }

        EncryptionKey key = new EncryptionKey(EncryptionType.DES_CBC_CRC, TESTKEY);

        newCksum = CheckSumHandler.checksumWithKey(testCase.cksumType, plainData, key.getKeyData(), KeyUsage.NONE);

        if (CheckSumHandler.verifyWithKey(newCksum, plainData, key.getKeyData(), KeyUsage.NONE)) {
            System.err.println("Checksum verifying is OK for " + testCase.cksumType.getName());
        } else {
            System.err.println("Checksum verifying failed for " + testCase.cksumType.getName());
        }

        // corrupt and verify again
        byte[] cont = newCksum.getChecksum();
        cont[0]++;
        newCksum.setChecksum(cont);
        if (CheckSumHandler.verifyWithKey(newCksum, plainData, key.getKeyData(), KeyUsage.NONE)) {
            System.err.println("Checksum verifying failed with corrupt data for " + testCase.cksumType.getName());
        } else {
            System.err.println("Checksum verifying is OK with corrupt data for " + testCase.cksumType.getName());
        }

        CheckSum knwnCksum = new CheckSum(testCase.cksumType, knownChecksum);
        if (CheckSumHandler.verifyWithKey(knwnCksum, plainData, key.getKeyData(), KeyUsage.NONE)) {
            System.err.println("Checksum verifying is OK with known checksum for " + testCase.cksumType.getName());
        } else {
            System.err.println("Checksum verifying failed with known checksum for " + testCase.cksumType.getName());
        }
    }
}
