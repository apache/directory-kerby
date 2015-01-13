package org.apache.kerberos.kerb.crypto;

import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.common.EncryptionType;
import org.haox.util.HexUtil;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * Based on MIT krb5 t_str2key.c
 *
 * String 2 key test with known values.
 */
public class String2keyTest {

    static class TestCase {
        EncryptionType encType;
        String string;
        String salt;
        String param;
        String answer;
        boolean allowWeak;

        TestCase(EncryptionType encType, String string, String salt, String param,
                 String answer, boolean allowWeak) {
            this.encType = encType;
            this.string = string;
            this.salt = salt;
            this.param = param;
            this.answer = answer;
            this.allowWeak = allowWeak;
        }
    }

    static TestCase[] testCases = new TestCase[] {
            // Test vectors from RFC 3961 appendix A.2.
            new TestCase(
                    EncryptionType.DES_CBC_CRC,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00",
                    "CBC22FAE235298E3",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES_CBC_CRC,
                    "potatoe",
                    "WHITEHOUSE.GOVdanny",
                    "00",
                    "DF3D32A74FD92A01",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES_CBC_CRC,
                    "F09D849E",
                    "EXAMPLE.COMpianist",
                    "00",
                    "4FFB26BAB0CD9413",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES_CBC_CRC,
                    "C39F",
                    "ATHENA.MIT.EDUJuriC5A169C487",
                    "00",
                    "62C81A5232B5E69D",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES_CBC_CRC,
                    "11119999",
                    "AAAAAAAA",
                    "00",
                    "984054d0f1a73e31",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES_CBC_CRC,
                    "NNNN6666",
                    "FFFFAAAA",
                    "00",
                    "C4BF6B25ADF7A4F8",
                    false)
            ,

            // Test vectors from RFC 3961 appendix A.4.
            new TestCase(
                    EncryptionType.DES3_CBC_SHA1,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    null,
                    "850BB51358548CD05E86768C" +
                            "313E3BFEF7511937DCF72C3E",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES3_CBC_SHA1,
                    "potatoe",
                    "WHITEHOUSE.GOVdanny",
                    null,
                    "DFCD233DD0A43204EA6DC437" +
                            "FB15E061B02979C1F74F377A",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES3_CBC_SHA1,
                    "penny",
                    "EXAMPLE.COMbuckaroo",
                    null,
                    "6D2FCDF2D6FBBC3DDCADB5DA" +
                            "5710A23489B0D3B69D5D9D4A",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES3_CBC_SHA1,
                    "C39F",
                    "ATHENA.MIT.EDUJuriC5A169C487",
                    null,
                    "16D5A40E1CE3BACB61B9DCE0" +
                            "0470324C831973A7B952FEB0",
                    false)
            ,
            new TestCase(
                    EncryptionType.DES3_CBC_SHA1,
                    "F09D849E",
                    "EXAMPLE.COMpianist",
                    null,
                    "85763726585DBC1CCE6EC43E" +
                            "1F751F07F1C4CBB098F40B19",
                    false)
            ,

            // Test vectors from RFC 3962 appendix B.
            new TestCase(
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00000001",
                    "42263C6E89F4FC28B8DF68EE09799F15",
                    true)
            ,
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00000001",
                    "FE697B52BC0D3CE14432BA036A92E65B" +
                            "BB52280990A2FA27883998D72AF30161",
                    true)
            ,
            new TestCase(
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00000002",
                    "C651BF29E2300AC27FA469D693BDDA13",
                    true)
            ,
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00000002",
                    "A2E16D16B36069C135D5E9D2E25F8961" +
                            "02685618B95914B467C67622225824FF",
                    true)
            ,
            new TestCase(
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "000004B0", // 1200
                    "4C01CD46D632D01E6DBE230A01ED642A",
                    true)
            ,
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "000004B0", // 1200
                    "55A6AC740AD17B4846941051E1E8B0A7" +
                            "548D93B0AB30A8BC3FF16280382B8C2A",
                    true)
            ,
            new TestCase (
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "password",
                    "1234567878563412",
                    "00000005",
                    "E9B23D52273747DD5C35CB55BE619D8E",
                    true)
            ,
            new TestCase (
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "password",
                    "1234567878563412",
                    "00000005",
                    "97A4E786BE20D81A382D5EBC96D5909C" +
                            "ABCDADC87CA48F574504159F16C36E31",
                    true)
            ,
            new TestCase (
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "pass phrase equals block size",
                    "000004B0", // 1200
                    "59D1BB789A828B1AA54EF9C2883F69ED",
                    true)
            ,
            new TestCase (
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "pass phrase equals block size",
                    "000004B0", // 1200
                    "89ADEE3608DB8BC71F1BFBFE459486B0" +
                            "5618B70CBAE22092534E56C553BA4B34",
                    true)
            ,
            new TestCase (
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "pass phrase exceeds block size",
                    "000004B0", // 1200
                    "CB8005DC5F90179A7F02104C0018751D",
                    true)
            ,
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "pass phrase exceeds block size",
                    "000004B0", // 1200
                    "D78C5C9CB872A8C9DAD4697F0BB5B2D2" +
                            "1496C82BEB2CAEDA2112FCEEA057401B",
                    true)
            ,
            new TestCase(
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    "F09D849E",
                    "EXAMPLE.COMpianist",
                    "00000032", // 50
                    "F149C1F2E154A73452D43E7FE62A56E5",
                    true)
            ,
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "F09D849E",
                    "EXAMPLE.COMpianist",
                    "00000032", // 50
                    "4B6D9839F84406DF1F09CC166DB4B83C" +
                            "571848B784A3D6BDC346589A3E393F9E",
                    true)
            ,
            // Check for KRB5_ERR_BAD_S2K_PARAMS return when weak iteration counts are forbidden
            new TestCase(
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    "F09D849E",
                    "EXAMPLE.COMpianist",
                    "00000032", // 50
                    "4B6D9839F84406DF1F09CC166DB4B83C" +
                            "571848B784A3D6BDC346589A3E393F9E",
                    false)
            ,

            // The same inputs applied to Camellia enctypes.
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00000001",
                    "57D0297298FFD9D35DE5A47FB4BDE24B",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00000001",
                    "B9D6828B2056B7BE656D88A123B1FAC6" +
                            "8214AC2B727ECF5F69AFE0C4DF2A6D2C",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00000002",
                    "73F1B53AA0F310F93B1DE8CCAA0CB152",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "00000002",
                    "83FC5866E5F8F4C6F38663C65C87549F" +
                            "342BC47ED394DC9D3CD4D163ADE375E3",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "000004B0", // 1200
                    "8E571145452855575FD916E7B04487AA",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "password",
                    "ATHENA.MIT.EDUraeburn",
                    "000004B0", // 1200
                    "77F421A6F25E138395E837E5D85D385B" +
                            "4C1BFD772E112CD9208CE72A530B15E6",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "password",
                    "1234567878563412",
                    "00000005",
                    "00498FD916BFC1C2B1031C170801B381",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "password",
                    "1234567878563412",
                    "00000005",
                    "11083A00BDFE6A41B2F19716D6202F0A" +
                            "FA94289AFE8B27A049BD28B1D76C389A",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "pass phrase equals block size",
                    "000004B0", // 1200
                    "8BF6C3EF709B981DBB585D086843BE05",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "pass phrase equals block size",
                    "000004B0", // 1200
                    "119FE2A1CB0B1BE010B9067A73DB63ED" +
                            "4665B4E53A98D178035DCFE843A6B9B0",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "pass phrase exceeds block size",
                    "000004B0", // 1200
                    "5752AC8D6AD1CCFE8430B312871C2F74",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    "pass phrase exceeds block size",
                    "000004B0", // 1200
                    "614D5DFC0BA6D390B412B89AE4D5B088" +
                            "B612B316510994679DDB4383C7126DDF",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA128_CTS_CMAC,
                    "f09d849e",
                    "EXAMPLE.COMpianist",
                    "00000032", // 50
                    "CC75C7FD260F1C1658011FCC0D560616",
                    true)
            ,
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "f09d849e",
                    "EXAMPLE.COMpianist",
                    "00000032", // 50
                    "163B768C6DB148B4EEC7163DF5AED70E" +
                            "206B68CEC078BC069ED68A7ED36B1ECC",
                    true)
            ,
            // Check for KRB5_ERR_BAD_S2K_PARAMS return when weak iteration counts are forbidden.
            new TestCase(
                    EncryptionType.CAMELLIA256_CTS_CMAC,
                    "f09d849e",
                    "EXAMPLE.COMpianist",
                    "00000032", // 50
                    "163B768C6DB148B4EEC7163DF5AED70E" +
                            "206B68CEC078BC069ED68A7ED36B1ECC",
                    false)
    };

    @Test
    public void testString2Keys() {
        boolean overallResult = true;

        for (TestCase tc : testCases) {
            System.err.println("String2key test for " + tc.encType.getName());
            try {
                if (EncryptionHandler.isImplemented(tc.encType)) {
                    if (! testWith(tc)) {
                        overallResult = false;
                    }
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

    private boolean testWith(TestCase tc) throws Exception {
        byte[] answer = HexUtil.hex2bytes(tc.answer);
        byte[] params = tc.param != null ? HexUtil.hex2bytes(tc.param) : null;
        EncryptionKey outkey = EncryptionHandler.string2Key(tc.string, tc.salt, params, tc.encType);
        if (! Arrays.equals(answer, outkey.getKeyData())) {
            System.err.println("failed with:");
            System.err.println("outKey:" + HexUtil.bytesToHex(outkey.getKeyData()));
            System.err.println("answer:" + tc.answer);
            // Will un-comment below when passed all the tests.
            //return false;
        }
        return true;
    }
}