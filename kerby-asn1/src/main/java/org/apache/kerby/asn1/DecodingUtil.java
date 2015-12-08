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

import org.apache.kerby.asn1.parse.Asn1ParsingResult;
import org.apache.kerby.asn1.type.Asn1Collection;
import org.apache.kerby.asn1.type.Asn1Constructed;
import org.apache.kerby.asn1.type.Asn1Object;
import org.apache.kerby.asn1.type.Asn1Simple;
import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;

public class DecodingUtil {

    public static Asn1Type decodeValue(Asn1ParsingResult parsingResult) throws IOException {
        if (Asn1Simple.isSimple(parsingResult.tag())) {
            return DecodingUtil.decodeValueAsSimple(parsingResult);
        } else if (Asn1Collection.isCollection(parsingResult.tag())) {
            return DecodingUtil.decodeValueAsCollection(parsingResult);
        } else if (!parsingResult.tag().isPrimitive()) {
            Asn1Object tmpValue = new Asn1Constructed(parsingResult.tag());
            tmpValue.decode(parsingResult);
            return tmpValue;
        } else {
            throw new IOException("Unknow type of tag=" + parsingResult.tag());
        }
    }

    public static Asn1Type decodeValueAsSimple(Asn1ParsingResult parsingResult) throws IOException {
        Asn1Object value = (Asn1Object) Asn1Simple.createSimple(parsingResult.tagNo());
        value.useDefinitiveLength(parsingResult.isDefinitiveLength());
        decodeValueWith(parsingResult, value);
        return value;
    }

    public static Asn1Type decodeValueAsCollection(Asn1ParsingResult parsingResult) throws IOException {
        Asn1Collection value = Asn1Collection.createCollection(parsingResult.tag());
        value.useDefinitiveLength(parsingResult.isDefinitiveLength());
        value.setLazy(true);
        decodeValueWith(parsingResult, value);
        return value;
    }

    public static Asn1Type decodeValueAs(Asn1ParsingResult parsingResult,
                                         Class<? extends Asn1Type> type) throws IOException {
        Asn1Type value;
        try {
            value = type.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Invalid type: "
                + type.getCanonicalName(), e);
        }
        decodeValueWith(parsingResult, value);
        return value;
    }

    public static void decodeValueWith(Asn1ParsingResult parsingResult, Asn1Type value) throws IOException {
        value.useDefinitiveLength(parsingResult.isDefinitiveLength());
        ((Asn1Object) value).decode(parsingResult);
    }

    public static void decodeValueWith(Asn1ParsingResult parsingResult,
                                       Asn1Type value, TaggingOption taggingOption) throws IOException {
        if (!parsingResult.isTagSpecific()) {
            throw new IllegalArgumentException(
                "Attempting to decode non-tagged value using tagging way");
        }
        ((Asn1Object) value).taggedDecode(parsingResult, taggingOption);
    }
}
