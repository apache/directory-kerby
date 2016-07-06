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
package org.apache.kerby.xdr;

import org.apache.kerby.xdr.util.HexUtil;
import org.apache.kerby.xdr.util.IOUtil;

import java.io.IOException;
import java.io.InputStream;

public final class TestUtil {
    private TestUtil() {

    }

    static byte[] readBytesFromTxtFile(String resource) throws IOException {
        String hexStr = readStringFromTxtFile(resource);
        return HexUtil.hex2bytes(hexStr);
    }

    static String readStringFromTxtFile(String resource) throws IOException {
        InputStream is = TestUtil.class.getResourceAsStream(resource);
        return IOUtil.readInput(is);
    }

    static byte[] readBytesFromBinFile(String resource) throws IOException {
        InputStream is = TestUtil.class.getResourceAsStream(resource);
        return IOUtil.readInputStream(is);
    }
}
