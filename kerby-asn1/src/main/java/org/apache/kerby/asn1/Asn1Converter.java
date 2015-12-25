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

import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.type.Asn1Specific;
import org.apache.kerby.asn1.type.Asn1Collection;
import org.apache.kerby.asn1.type.Asn1Constructed;
import org.apache.kerby.asn1.type.Asn1Encodeable;
import org.apache.kerby.asn1.type.Asn1Simple;
import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;

/**
 * Converting a ASN1 parsing result into an ASN1 object.
 */
public final class Asn1Converter {

    private Asn1Converter() {

    }

    public static Asn1Type convert(Asn1ParseResult parseResult,
                                   boolean isLazy) throws IOException {
        if (Asn1Simple.isSimple(parseResult.tag())) {
            return Asn1Converter.convertAsSimple(parseResult);
        } else if (Asn1Collection.isCollection(parseResult.tag())) {
            return Asn1Converter.convertAsCollection(parseResult, isLazy);
        } else if (!parseResult.tag().isPrimitive()) {
            Asn1Encodeable tmpValue = new Asn1Constructed(parseResult.tag());
            tmpValue.decode(parseResult);
            return tmpValue;
        } else if (parseResult.isTagSpecific()) {
            Asn1Specific app = new Asn1Specific(parseResult.tag());
            app.decode(parseResult);
            return app;
        } else {
            throw new IOException("Unexpected item: " + parseResult.simpleInfo());
        }
    }

    public static Asn1Type convertAsSimple(Asn1ParseResult parseResult) throws IOException {
        Asn1Encodeable value = Asn1Simple.createSimple(parseResult.tagNo());
        value.useDefinitiveLength(parseResult.isDefinitiveLength());
        Asn1Binder.bind(parseResult, value);
        return value;
    }

    public static Asn1Type convertAsCollection(Asn1ParseResult parseResult,
                                               boolean isLazy) throws IOException {
        Asn1Collection value = Asn1Collection.createCollection(parseResult.tag());
        value.useDefinitiveLength(parseResult.isDefinitiveLength());
        value.setLazy(isLazy);
        Asn1Binder.bind(parseResult, value);
        return value;
    }

    public static Asn1Type convertAs(Asn1ParseResult parseResult,
                                     Class<? extends Asn1Type> type) throws IOException {
        Asn1Type value;
        try {
            value = type.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Invalid type: "
                + type.getCanonicalName(), e);
        }
        Asn1Binder.bind(parseResult, value);
        return value;
    }
}
