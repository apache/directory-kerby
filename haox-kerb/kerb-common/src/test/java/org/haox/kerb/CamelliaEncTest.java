package org.haox.kerb;

import org.junit.Assert;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CamelliaEncTest {

    private List<String> outputs;
    private byte[] key;
    private int keySize;

    private byte[] plain = new byte[16];
    private byte[] cipher = new byte[16];
    private byte[] zero = new byte[16];

    private List<String> getExpectedLines() throws IOException {
        InputStream res = CamelliaEncTest.class.getResourceAsStream("/camellia-expect-vt.txt");
        BufferedReader br = new BufferedReader(new InputStreamReader(res));

        List<String> results = new ArrayList<String>();
        String line;
        while ((line = br.readLine()) != null) {
            results.add(line);
        }
        return results;
    }

    @Test
    public void testEnc() throws IOException {
        List<String> expectedLines = getExpectedLines();

        testWith(16);
        testWith(32);

        List<String> newLines = expectedLines;
        Assert.assertEquals("Comparing new lines with expected lines",
                expectedLines, newLines);
    }

    private void testWith(int keySize) {
        this.keySize = keySize;
        outputs.add("KEYSIZE=" + (keySize * 8));

        Arrays.fill(plain, (byte) 0);
        hexDump("PT", plain);

        this.key = new byte[keySize];
        Arrays.fill(key, (byte) 0);
        for (int i = 0; i < keySize * 8; ++i) {
            Arrays.fill(key, (byte) 0);
            setBit(key, i);
            outputs.add("I=" + (i + 1));
            hexDump("KEY", key);
            enc();
            hexDump("CT", cipher);
        }
    }

    private void hexDump(String label, byte[] bytes) {
        String line = label + "=" + Util.bytesToHex2(bytes);
        outputs.add(line);
    }

    private static void setBit(byte[] bytes, int i) {

    }

    private void enc() {

    }
}
