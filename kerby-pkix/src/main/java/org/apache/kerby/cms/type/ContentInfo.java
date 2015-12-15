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

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.Asn1Type;

import static org.apache.kerby.cms.type.ContentInfo.MyEnum.CONTENT;
import static org.apache.kerby.cms.type.ContentInfo.MyEnum.CONTENT_TYPE;

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
    protected enum MyEnum implements EnumType {
        CONTENT_TYPE,
        CONTENT;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

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

    public <T extends Asn1Type> T getContentAs(Class<T> t) {
        return getFieldAsAny(CONTENT, t);
    }

    public void setContent(Asn1Type content) {
        setFieldAsAny(CONTENT, content);
    }
}
