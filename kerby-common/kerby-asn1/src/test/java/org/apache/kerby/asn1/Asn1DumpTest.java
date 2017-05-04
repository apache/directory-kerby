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

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class Asn1DumpTest {

    @Test
    @org.junit.Ignore
    public void testDumpWithPersonnelRecord() throws IOException {
        try {
            PersonnelRecord pr = DataTest.createSamplePersonnel();
            Asn1.dump(pr);

            byte[] data = DataTest.createSammplePersonnelEncodingData();
            Asn1.parseAndDump(data);
            Asn1.decodeAndDump(data);
        } catch (Exception e) {
            Assert.fail("Test dump with personnel record failed. "
                    + e.toString());
        }
    }

    @Test
    @org.junit.Ignore
    public void testDumpWithCompressedData() throws IOException {
        String hexStr = TestUtil.readStringFromTxtFile("/compressed-data.txt");
        try {
            Asn1.parseAndDump(hexStr);
            Asn1.decodeAndDump(hexStr);
        } catch (Exception e) {
            Assert.fail("Test dump with compressed data failed. "
                    + e.toString());
        }
    }

    @Test
    @org.junit.Ignore
    public void testDumpWithSignedData() throws IOException {
        String hexStr = TestUtil.readStringFromTxtFile("/signed-data.txt");
        try {
            Asn1.parseAndDump(hexStr);
            Asn1.decodeAndDump(hexStr);
        } catch (Exception e) {
            Assert.fail("test dump with signed data from file: "
                    + "signed-data.txt failed. " + e.toString());
        }
    }

    @Test
    @org.junit.Ignore
    public void testDumpWithDerData() throws IOException {
        byte[] data = TestUtil.readBytesFromBinFile("/der-data.dat");
        try {
            Asn1.parseAndDump(data);
            Asn1.decodeAndDump(data);
        } catch (Exception e) {
            Assert.fail("test dump with derData from file: "
                    + "der-data.dat failed. " + e.toString());
        }
    }

    @Test
    public void testDumpWithEmptyContainer() throws IOException {
        byte[] data = TestUtil.readBytesFromTxtFile("/empty-container.txt");
        try {
            Asn1.parseAndDump(data);
            Asn1.decodeAndDump(data);
        } catch (Exception e) {
            Assert.fail("test dump with empty container from file: "
                    + "empty-container.txt failed. " + e.toString());
        }
    }
}
