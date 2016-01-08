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
package org.apache.kerby.util;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.assertTrue;


public class Base64Test {

    @Test
    public void testOrigBase64() throws Exception {
        Random random = new Random();
        for (int i = 0; i < 4567; i++) {
            byte[] buf = new byte[i];
            random.nextBytes(buf);
            byte[] enc = Base64.encodeBase64(buf);
            ByteArrayInputStream in = new ByteArrayInputStream(enc);
            enc = Util.streamToBytes(in);
            byte[] dec = Base64.decodeBase64(enc);
            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("testOrigBase64 Failed on : " + i);
            }
            assertTrue(result);
        }
        for (int i = 5; i < 50; i++) {
            int testSize = i * 1000 + 123;
            byte[] buf = new byte[testSize];
            random.nextBytes(buf);
            byte[] enc = Base64.encodeBase64(buf);
            ByteArrayInputStream in = new ByteArrayInputStream(enc);
            enc = Util.streamToBytes(in);            
            byte[] dec = Base64.decodeBase64(enc);
            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("testOrigBase64 Failed on : " + testSize);
            }
            assertTrue(result);
        }
    }

    @Test
    public void testBase64() throws Exception {
        Random random = new Random();
        for (int i = 0; i < 4567; i++) {
            byte[] buf = new byte[i];
            random.nextBytes(buf);

            ByteArrayInputStream in = new ByteArrayInputStream(buf);
            Base64InputStream base64 = new Base64InputStream(in, true);
            byte[] enc = Util.streamToBytes(base64);
            in = new ByteArrayInputStream(enc);
            base64 = new Base64InputStream(in);
            byte[] dec = Util.streamToBytes(base64);

            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("testBase64 Failed on : " + i);
            }
            assertTrue(result);
        }
        for (int i = 5; i < 50; i++) {
            int testSize = i * 1000 + 123;
            byte[] buf = new byte[testSize];
            random.nextBytes(buf);

            ByteArrayInputStream in = new ByteArrayInputStream(buf);
            Base64InputStream base64 = new Base64InputStream(in, true);
            byte[] enc = Util.streamToBytes(base64);
            in = new ByteArrayInputStream(enc);
            base64 = new Base64InputStream(in);
            byte[] dec = Util.streamToBytes(base64);

            boolean result = Arrays.equals(buf, dec);
            if (!result) {
                System.out.println();
                System.out.println("testBase64 Failed on : " + testSize);
            }
            assertTrue(result);
        }

    }
}
