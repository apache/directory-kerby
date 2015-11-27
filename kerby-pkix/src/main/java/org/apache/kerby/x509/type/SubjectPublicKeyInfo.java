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

import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *    algorithm            AlgorithmIdentifier,
 *    subjectPublicKey     BIT STRING
 * }
 */
public class SubjectPublicKeyInfo extends Asn1SequenceType {
    private static final int ALGORITHM = 0;
    private static final int SUBJECT_PUBLIC_KEY = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ALGORITHM, AlgorithmIdentifier.class),
            new Asn1FieldInfo(SUBJECT_PUBLIC_KEY, Asn1BitString.class)
    };

    public SubjectPublicKeyInfo() {
        super(fieldInfos);
    }

    public AlgorithmIdentifier getAlgorithm() {
        return getFieldAs(ALGORITHM, AlgorithmIdentifier.class);
    }

    public void setAlgorithm(AlgorithmIdentifier algorithm) {
        setFieldAs(ALGORITHM, algorithm);
    }

    public byte[] getSubjectPubKey() {
        return getFieldAsOctets(SUBJECT_PUBLIC_KEY);
    }

    public void setSubjectPubKey(byte[] subjectPubKey) {
        setFieldAs(SUBJECT_PUBLIC_KEY, new Asn1BitString(subjectPubKey));
    }
}
