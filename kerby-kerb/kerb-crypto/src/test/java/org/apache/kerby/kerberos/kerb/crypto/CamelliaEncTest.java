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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Camellia128Provider;
import org.apache.kerby.kerberos.kerb.crypto.enc.provider.Camellia256Provider;
import org.apache.kerby.util.HexUtil;
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

    private List<String> outputs = new ArrayList<String>();
    private int keySize;

    private byte[] plain = new byte[16];
    private byte[] cipher = new byte[16];
    private EncryptProvider encProvider;

    private List<String> getExpectedLines() throws IOException {
        InputStream res = CamelliaEncTest.class.getResourceAsStream("/camellia-expect-vt.txt");
        BufferedReader br = new BufferedReader(new InputStreamReader(res));

        List<String> results = new ArrayList<String>();
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (! line.isEmpty()) {
                results.add(line);
            }
        }
        return results;
    }

    @Test
    public void testEnc() throws IOException, KrbException {
        List<String> expectedLines = getExpectedLines();

        testWith(16);
        outputs.add("==========");
        testWith(32);
        outputs.add("==========");

        List<String> newLines = expectedLines;
        Assert.assertEquals("Comparing new lines with expected lines",
                expectedLines, outputs);
    }

    private void testWith(int keySize) throws KrbException {
        this.keySize = keySize;
        outputs.add("KEYSIZE=" + (keySize * 8));

        encProvider = keySize == 16 ?
                new Camellia128Provider() : new Camellia256Provider();

        byte[] key = new byte[keySize];
        Arrays.fill(key, (byte) 0);
        hexDump("KEY", key);

        for (int i = 0; i < 16 * 8; ++i) {
            Arrays.fill(plain, (byte) 0);
            setBit(plain, i);
            outputs.add("I=" + (i + 1));
            hexDump("PT", plain);
            encWith(key);
            hexDump("CT", cipher);
        }
    }

    private void hexDump(String label, byte[] bytes) {
        String line = label + "=" + HexUtil.bytesToHex(bytes);
        outputs.add(line);
    }

    private static void setBit(byte[] bytes, int bitnum) {
        int bytenum = bitnum / 8;
        bitnum %= 8;
        // First bit is the high bit!
        bytes[bytenum] = (byte) (1 << (7 - bitnum));
    }

    private void encWith(byte[] key) throws KrbException {
        System.arraycopy(plain, 0, cipher, 0, plain.length);
        encProvider.encrypt(key, cipher);
    }
}
