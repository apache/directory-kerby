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
package org.apache.kerby.asn1.type;

import org.apache.kerby.asn1.EncodingOption;
import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;

public class Asn1BmpString extends Asn1Simple<String> {
    public Asn1BmpString() {
        super(UniversalTag.BMP_STRING);
    }

    public Asn1BmpString(String value) {
        super(UniversalTag.BMP_STRING, value);
    }

    @Override
    protected int encodingBodyLength() {
        return getValue().length() * 2;
    }

    protected void toBytes(EncodingOption encodingOption) {
        String strValue = getValue();
        int len = strValue.length();
        byte[] bytes = new byte[len * 2];
        
        for (int i = 0; i != len; i++) {
            char c = strValue.charAt(i);
            bytes[2 * i] = (byte) (c >> 8);
            bytes[2 * i + 1] = (byte) c;
        }
        setBytes(bytes);
    }

    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        char[] chars = new char[bytes.length / 2];
        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) ((bytes[2 * i] << 8) | (bytes[2 * i + 1] & 0xff));
        }
        setValue(new String(chars));
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        if (content.hasLeft() % 2 != 0) {
            throw new IOException("Bad stream, BMP string expecting multiple of 2 bytes");
        }
        super.decodeBody(content);
    }
}
