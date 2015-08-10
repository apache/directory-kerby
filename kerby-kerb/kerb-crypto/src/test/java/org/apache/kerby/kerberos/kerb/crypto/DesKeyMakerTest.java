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

import org.apache.kerby.kerberos.kerb.crypto.key.DesKeyMaker;
import org.apache.kerby.util.HexUtil;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This is just for my experimental tweaking, so pleas bear it.
 */
public class DesKeyMakerTest {

    /**
     * The class used to store the test values
     */
    private static final class TestCase {
        String salt;
        String passwd;
        String passwdSaltBytes;
        String fanFoldedKey;
        String intermediateKey;
        String finalKey;

        private TestCase(String salt, String passwd, String passwdSaltBytes,
                         String fanFoldedKey, String intermediateKey, String finalKey) {
            this.salt = salt;
            this.passwd = passwd;
            this.passwdSaltBytes = passwdSaltBytes;
            this.fanFoldedKey = fanFoldedKey;
            this.intermediateKey = intermediateKey;
            this.finalKey = finalKey;
        }
    }

    /**
     * Actually do the test
     */
    private void test(TestCase tc) {
        byte[] expectedValue = HexUtil.hex2bytes(tc.passwdSaltBytes);
        byte[] value = DesKeyMaker.makePasswdSalt(tc.passwd, tc.salt);
        assertThat(value).as("PasswdSalt bytes").isEqualTo(expectedValue);

        expectedValue = HexUtil.hex2bytes(tc.fanFoldedKey);
        value = DesKeyMaker.fanFold(tc.passwd, tc.salt, null);
        assertThat(value).as("FanFold result").isEqualTo(expectedValue);

        expectedValue = HexUtil.hex2bytes(tc.intermediateKey);
        value = DesKeyMaker.intermediateKey(value);
        assertThat(value).as("IntermediateKey result").isEqualTo(expectedValue);

        // finalKey check ignored here and it's done in String2keyTest.
    }

    /**
     * This is just for my experimental tweaking, so pleas bear it.
     */
    //@Test
    public void testCase1() {
        TestCase tc = new TestCase("ATHENA.MIT.EDUraeburn",
                "password", "70617373776f7264415448454e412e4d49542e4544557261656275726e",
                "c01e38688ac86c2e", "c11f38688ac86d2f", "cbc22fae235298e3");

        test(tc);
    }
}
