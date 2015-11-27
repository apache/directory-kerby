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


import org.apache.kerby.asn1.type.*;

/**
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *    algorithm               OBJECT IDENTIFIER,
 *    parameters              ANY DEFINED BY algorithm OPTIONAL
 * }
 */
public class AlgorithmIdentifier extends Asn1SequenceType {
    private static final int ALGORITHM = 0;
    private static final int PARAMETERS = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ALGORITHM, Asn1ObjectIdentifier.class),
            new Asn1FieldInfo(PARAMETERS, Asn1Any.class)
    };

    public AlgorithmIdentifier() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getAlgorithm() {
        return getFieldAs(ALGORITHM, Asn1ObjectIdentifier.class);
    }

    public void setAlgorithm(Asn1ObjectIdentifier algorithm) {
        setFieldAs(ALGORITHM, algorithm);
    }

    public Asn1Type getParameters() {
        return getFieldAsAny(PARAMETERS);
    }

    public void setParameters(Asn1Type parameters) {
        setFieldAsAny(PARAMETERS, parameters);
    }
}
