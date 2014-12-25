package org.haox.kerb;

import org.haox.kerb.crypto.CheckSumHandler;
import org.haox.kerb.spec.common.*;
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
                    "e3f76a07f3401e3536b43a3f54226c39422c35682c354835"
            ),
            new CksumTest(
                    CheckSumType.RSA_MD5_DES,
                    "this is a test",
                    "e3f76a07f3401e351143ee6f4c09be1edb4264d55015db53"
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
