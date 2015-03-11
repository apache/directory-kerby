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
import org.apache.kerby.kerberos.kerb.crypto.util.Cmac;
import org.apache.kerby.util.HexUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class CmacTest {

    /* All examples use the following Camellia-128 key. */
    static String keyBytes = "2b7e151628aed2a6" +
            "abf7158809cf4f3c";

    /* Example inputs are this message truncated to 0, 16, 40, and 64 bytes. */
    static String inputBytes = "6bc1bee22e409f96" +
            "e93d7e117393172a" +
            "ae2d8a571e03ac9c" +
            "9eb76fac45af8e51" +
            "30c81c46a35ce411" +
            "e5fbc1191a0a52ef" +
            "f69f2445df4f9b17" +
            "ad2b417be66c3710";

    /* Expected result of CMAC on empty inputBytes. */
    static String cmac1 = "ba925782aaa1f5d9" +
            "a00f89648094fc71";

    /* Expected result of CMAC on first 16 bytes of inputBytes. */
    static String cmac2 = "6d962854a3b9fda5" +
            "6d7d45a95ee17993";

    /* Expected result of CMAC on first 40 bytes of inputBytes. */
    static String cmac3 = "5c18d119ccd67661" +
            "44ac1866131d9f22";

    /* Expected result of CMAC on all 64 bytes of inputBytes. */
    static String cmac4 = "c2699a6eba55ce9d" +
            "939a8a4e19466ee9";


    @Test
    public void testCmac() throws KrbException, KrbException {
        byte[] key = HexUtil.hex2bytes(keyBytes);
        byte[] input = HexUtil.hex2bytes(inputBytes);
        EncryptProvider encProvider = new Camellia128Provider();

        // test 1
        byte[] result = Cmac.cmac(encProvider, key, input, 0, 0);
        assertThat(result).as("Test 1").isEqualTo(HexUtil.hex2bytes(cmac1));

        // test 2
        result = Cmac.cmac(encProvider, key, input, 0, 16);
        assertThat(result).as("Test 2").isEqualTo(HexUtil.hex2bytes(cmac2));

        // test 3
        result = Cmac.cmac(encProvider, key, input, 0, 40);
        assertThat(result).as("Test 3").isEqualTo(HexUtil.hex2bytes(cmac3));

        // test 4
        result = Cmac.cmac(encProvider, key, input, 0, 64);
        assertThat(result).as("Test 4").isEqualTo(HexUtil.hex2bytes(cmac4));
    }
}
