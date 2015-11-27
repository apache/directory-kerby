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

/**
 * OtherRevocationInfoFormat ::= SEQUENCE {
 *   otherRevInfoFormat OBJECT IDENTIFIER,
 *   otherRevInfo ANY DEFINED BY otherRevInfoFormat
 * }
 */
public class OtherRevocationInfoFormat extends Asn1SequenceType {
    private static final int OTHER_REV_INFO_FORMAT = 0;
    private static final int OTHER_REV_INFO = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(OTHER_REV_INFO_FORMAT, Asn1ObjectIdentifier.class),
            new Asn1FieldInfo(OTHER_REV_INFO, Asn1Any.class)
    };

    public OtherRevocationInfoFormat() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getOtherRevInfoFormat() {
        return getFieldAs(OTHER_REV_INFO_FORMAT, Asn1ObjectIdentifier.class);
    }

    public void setOtherRevInfoFormat(Asn1ObjectIdentifier otherRevInfoFormat) {
        setFieldAs(OTHER_REV_INFO_FORMAT, otherRevInfoFormat);
    }

    public Asn1Type getOtherRevInfo() {
        return getFieldAsAny(OTHER_REV_INFO);
    }

    public void setOtherRevInfo(Asn1Type otherRevInfo) {
        setFieldAsAny(OTHER_REV_INFO, otherRevInfo);
    }
}
