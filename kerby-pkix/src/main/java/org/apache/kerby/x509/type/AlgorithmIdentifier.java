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
import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.Asn1Type;

/**
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *    algorithm               OBJECT IDENTIFIER,
 *    parameters              ANY DEFINED BY algorithm OPTIONAL
 * }
 */

public class AlgorithmIdentifier extends Asn1SequenceType {
    protected enum AlgorithmIdentifierField implements EnumType {
        ALGORITHM,
        PARAMETERS;

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
            new Asn1FieldInfo(AlgorithmIdentifierField.ALGORITHM, Asn1ObjectIdentifier.class),
            new Asn1FieldInfo(AlgorithmIdentifierField.PARAMETERS, Asn1Any.class)
    };

    public AlgorithmIdentifier() {
        super(fieldInfos);
    }

    public String getAlgorithm() {
        return getFieldAsObjId(AlgorithmIdentifierField.ALGORITHM);
    }

    public void setAlgorithm(String algorithm) {
        setFieldAsObjId(AlgorithmIdentifierField.ALGORITHM, algorithm);
    }

    public <T extends Asn1Type> T getParametersAs(Class<T> t) {
        return getFieldAsAny(AlgorithmIdentifierField.PARAMETERS, t);
    }

    public void setParameters(Asn1Type parameters) {
        setFieldAsAny(AlgorithmIdentifierField.PARAMETERS, parameters);
    }
}