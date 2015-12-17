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
import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.x509.type.AlgorithmIdentifier;

import static org.apache.kerby.cms.type.OriginatorPublicKey.MyEnum.*;

/**
 * OriginatorPublicKey ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier,
 *   publicKey BIT STRING }
 */
public class OriginatorPublicKey extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        ALGORITHM,
        PUBLIC_KEY;

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
            new Asn1FieldInfo(ALGORITHM, AlgorithmIdentifier.class),
            new Asn1FieldInfo(PUBLIC_KEY, Asn1BitString.class)
    };

    public OriginatorPublicKey() {
        super(fieldInfos);
    }

    public AlgorithmIdentifier getAlgorithm() {
        return getFieldAs(ALGORITHM, AlgorithmIdentifier.class);
    }

    public void setAlgorithm(AlgorithmIdentifier algorithm) {
        setFieldAs(ALGORITHM, algorithm);
    }

    public Asn1BitString getPublicKey() {
        return getFieldAs(PUBLIC_KEY, Asn1BitString.class);
    }

    public void setPublicKey(Asn1BitString publicKey) {
        setFieldAs(PUBLIC_KEY, publicKey);
    }
}
