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

import org.apache.kerby.util.HexUtil;
import org.junit.Assert;
import org.junit.Test;

public class Crc32Test {

    static class TestCase {
        String data;
        long answer;

        public TestCase(String data, long answer) {
            this.data = data;
            this.answer = answer;
        }
    }

    static TestCase[] testCases = new TestCase[] {
            new TestCase("01", 0x77073096),
            new TestCase("02", 0xee0e612c),
            new TestCase("04", 0x076dc419),
            new TestCase("08", 0x0edb8832),
            new TestCase("10", 0x1db71064),
            new TestCase("20", 0x3b6e20c8),
            new TestCase("40", 0x76dc4190),
            new TestCase("80", 0xedb88320),
            new TestCase("0100", 0x191b3141),
            new TestCase("0200", 0x32366282),
            new TestCase("0400", 0x646cc504),
            new TestCase("0800", 0xc8d98a08),
            new TestCase("1000", 0x4ac21251),
            new TestCase("2000", 0x958424a2),
            new TestCase("4000", 0xf0794f05),
            new TestCase("8000", 0x3b83984b),
            new TestCase("0001", 0x77073096),
            new TestCase("0002", 0xee0e612c),
            new TestCase("0004", 0x076dc419),
            new TestCase("0008", 0x0edb8832),
            new TestCase("0010", 0x1db71064),
            new TestCase("0020", 0x3b6e20c8),
            new TestCase("0040", 0x76dc4190),
            new TestCase("0080", 0xedb88320),
            new TestCase("01000000", 0xb8bc6765),
            new TestCase("02000000", 0xaa09c88b),
            new TestCase("04000000", 0x8f629757),
            new TestCase("08000000", 0xc5b428ef),
            new TestCase("10000000", 0x5019579f),
            new TestCase("20000000", 0xa032af3e),
            new TestCase("40000000", 0x9b14583d),
            new TestCase("80000000", 0xed59b63b),
            new TestCase("00010000", 0x01c26a37),
            new TestCase("00020000", 0x0384d46e),
            new TestCase("00040000", 0x0709a8dc),
            new TestCase("00080000", 0x0e1351b8),
            new TestCase("00100000", 0x1c26a370),
            new TestCase("00200000", 0x384d46e0),
            new TestCase("00400000", 0x709a8dc0),
            new TestCase("00800000", 0xe1351b80),
            new TestCase("00000100", 0x191b3141),
            new TestCase("00000200", 0x32366282),
            new TestCase("00000400", 0x646cc504),
            new TestCase("00000800", 0xc8d98a08),
            new TestCase("00001000", 0x4ac21251),
            new TestCase("00002000", 0x958424a2),
            new TestCase("00004000", 0xf0794f05),
            new TestCase("00008000", 0x3b83984b),
            new TestCase("00000001", 0x77073096),
            new TestCase("00000002", 0xee0e612c),
            new TestCase("00000004", 0x076dc419),
            new TestCase("00000008", 0x0edb8832),
            new TestCase("00000010", 0x1db71064),
            new TestCase("00000020", 0x3b6e20c8),
            new TestCase("00000040", 0x76dc4190),
            new TestCase("00000080", 0xedb88320),
            new TestCase("666F6F", 0x7332bc33),
            new TestCase("7465737430313233343536373839", 0xb83e88d6),
            new TestCase("4D4153534143485653455454532049" +
                    "4E53544954565445204F4620544543484E4F4C4F4759", 0xe34180f7)
    };

    @Test
    public void testCrc32() {
        boolean isOk = true;
        for (TestCase tc : testCases) {
            if (! testWith(tc)) {
                isOk = false;
                System.err.println("Test with data " + tc.data + " failed");
            }
        }

        Assert.assertTrue(isOk);
    }

    private boolean testWith(TestCase testCase) {
        byte[] data = HexUtil.hex2bytes(testCase.data);
        long value = Crc32.crc(0, data, 0, data.length);
        return value == testCase.answer;
    }
}
