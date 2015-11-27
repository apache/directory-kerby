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
package org.apache.kerby.cms.type;

import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.asn1.type.ExplicitField;

/**
 * Ref. RFC 5652
 *
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 */
public class ContentInfo extends Asn1SequenceType {
    private static final int CONTENT_TYPE = 0;
    private static final int CONTENT = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
        new Asn1FieldInfo(CONTENT_TYPE, Asn1ObjectIdentifier.class),
        new ExplicitField(CONTENT, 0, Asn1Any.class),
    };

    public ContentInfo() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getContentType() {
        return getFieldAs(CONTENT_TYPE, Asn1ObjectIdentifier.class);
    }

    public void setContentType(Asn1ObjectIdentifier contentType) {
        setFieldAs(CONTENT_TYPE, contentType);
    }

    public Asn1Type getContent() {
        return getFieldAsAny(CONTENT);
    }

    public void setContent(Asn1Type content) {
        setFieldAsAny(CONTENT, content);
    }
}
