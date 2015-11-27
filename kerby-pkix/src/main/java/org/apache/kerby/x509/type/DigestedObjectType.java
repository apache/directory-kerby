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

import org.apache.kerby.asn1.type.Asn1EnumType;
import org.apache.kerby.asn1.type.Asn1Enumerated;

/**
 *
 * <pre>
 *         digestedObjectType  ENUMERATED {
 *                 publicKey            (0),
 *                 publicKeyCert        (1),
 *                 otherObjectTypes     (2)
 *         }
 *   
 * </pre>
 * 
 */
enum DigestedObjectEnum implements Asn1EnumType {
    PUBLIC_KEY,
    PUBLIC_KEY_CERT,
    OTHER_OBJECT_TYPES;

    @Override
    public int getValue() {
        return ordinal();
    }
}

public class DigestedObjectType extends Asn1Enumerated<DigestedObjectEnum> {
    @Override
    public Asn1EnumType[] getAllEnumValues() {
        return DigestedObjectEnum.values();
    }
}
