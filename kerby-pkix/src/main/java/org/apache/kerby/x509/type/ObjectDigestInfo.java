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
package org.apache.kerby.x509.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 *
 * <pre>
 *    ObjectDigestInfo ::= SEQUENCE {
 *         digestedObjectType  ENUMERATED {
 *                 publicKey            (0),
 *                 publicKeyCert        (1),
 *                 otherObjectTypes     (2) },
 *                         -- otherObjectTypes MUST NOT
 *                         -- be used in this profile
 *         otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
 *         digestAlgorithm     AlgorithmIdentifier,
 *         objectDigest        BIT STRING
 *    }
 *   
 * </pre>
 * 
 */
public class ObjectDigestInfo extends Asn1SequenceType {
    protected enum ODInfoField implements EnumType {
        DIGESTED_OBJECT_TYPE,
        OTHER_OBJECT_TYPE_ID,
        DIGEST_ALGORITHM,
        OBJECT_DIGEST;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(ODInfoField.DIGESTED_OBJECT_TYPE, DigestedObjectType.class),
        new Asn1FieldInfo(ODInfoField.OTHER_OBJECT_TYPE_ID, Asn1ObjectIdentifier.class),
        new Asn1FieldInfo(ODInfoField.DIGEST_ALGORITHM, AlgorithmIdentifier.class),
        new Asn1FieldInfo(ODInfoField.OBJECT_DIGEST, Asn1BitString.class)
    };

    public ObjectDigestInfo() {
        super(fieldInfos);
    }

    public DigestedObjectType getDigestedObjectType() {
        return getFieldAs(ODInfoField.DIGESTED_OBJECT_TYPE, DigestedObjectType.class);
    }

    public void setDigestedObjectType(DigestedObjectType digestedObjectType) {
        setFieldAs(ODInfoField.DIGESTED_OBJECT_TYPE, digestedObjectType);
    }

    public Asn1ObjectIdentifier getOtherObjectTypeID() {
        return getFieldAs(ODInfoField.OTHER_OBJECT_TYPE_ID, Asn1ObjectIdentifier.class);
    }

    public void setOtherObjectTypeId(Asn1ObjectIdentifier otherObjectTypeID) {
        setFieldAs(ODInfoField.OTHER_OBJECT_TYPE_ID, otherObjectTypeID);
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return getFieldAs(ODInfoField.DIGEST_ALGORITHM, AlgorithmIdentifier.class);
    }

    public void setDigestAlgorithm(AlgorithmIdentifier digestAlgorithm) {
        setFieldAs(ODInfoField.DIGEST_ALGORITHM, digestAlgorithm);
    }

    public Asn1BitString getObjectDigest() {
        return getFieldAs(ODInfoField.OBJECT_DIGEST, Asn1BitString.class);
    }

    public void setObjectDigest(Asn1BitString objectDigest) {
        setFieldAs(ODInfoField.OBJECT_DIGEST, objectDigest);
    }
}
