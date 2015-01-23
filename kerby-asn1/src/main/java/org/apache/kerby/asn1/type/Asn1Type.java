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
import org.apache.kerby.asn1.TaggingOption;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface Asn1Type {
    public int tagFlags();
    public int tagNo();
    public void setEncodingOption(EncodingOption encodingOption);
    public int encodingLength();
    public byte[] encode();
    public void encode(ByteBuffer buffer);
    public void decode(byte[] content) throws IOException;
    public void decode(ByteBuffer content) throws IOException;
    public byte[] taggedEncode(TaggingOption taggingOption);
    public void taggedEncode(ByteBuffer buffer, TaggingOption taggingOption);
    public void taggedDecode(ByteBuffer content, TaggingOption taggingOption) throws IOException;
    public void taggedDecode(byte[] content, TaggingOption taggingOption) throws IOException;
}
