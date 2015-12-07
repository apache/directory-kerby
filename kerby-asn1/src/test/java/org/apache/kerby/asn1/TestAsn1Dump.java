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
package org.apache.kerby.asn1;

import org.apache.kerby.asn1.util.IOUtil;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

public class TestAsn1Dump {

    @Test
    public void testDump1WithPersonnelRecord() throws IOException {
        try {
            PersonnelRecord pr = TestData.createSamplePersonnel();
            Asn1.dump(pr);

            byte[] data = TestData.createSammplePersonnelEncodingData();
            Asn1.dump(data);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testDump1WithCompressedData() throws IOException {
        String hexStr = readTxtFile("/compressed-data.txt");
        try {
            Asn1.dump(hexStr);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testDump1WithSignedData() throws IOException {
        String hexStr = readTxtFile("/signed-data.txt");
        try {
            Asn1.dump(hexStr);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testDump1WithDerData() throws IOException {
        byte[] data = readBinFile("/der-data.dat");
        try {
            Asn1.dump(data);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail();
        }
    }

    static String readTxtFile(String resource) throws IOException {
        InputStream is = TestAsn1Dump.class.getResourceAsStream(resource);
        return IOUtil.readInput(is);
    }

    static byte[] readBinFile(String resource) throws IOException {
        InputStream is = TestAsn1Dump.class.getResourceAsStream(resource);
        return IOUtil.readInputStream(is);
    }
}
