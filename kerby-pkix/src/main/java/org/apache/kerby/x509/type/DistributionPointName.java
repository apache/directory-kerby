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

import org.apache.kerby.asn1.*;
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.x500.type.RelativeDistinguishedName;

import static org.apache.kerby.x509.type.DistributionPointName.MyEnum.*;

/**
 *
 * <pre>
 * DistributionPointName ::= CHOICE {
 *     fullName                 [0] GeneralNames,
 *     nameRelativeToCRLIssuer  [1] RDN
 * }
 * </pre>
 */
public class DistributionPointName extends Asn1Choice {
    protected enum MyEnum implements EnumType {
        FULL_NAME,
        NAME_RELATIVE_TO_CRL_ISSUER;

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
        new ExplicitField(FULL_NAME, GeneralNames.class),
        new ExplicitField(NAME_RELATIVE_TO_CRL_ISSUER, RelativeDistinguishedName.class)
    };

    public DistributionPointName() {
        super(fieldInfos);
    }

    public GeneralNames getFullName() {
        return getChoiceValueAs(FULL_NAME, GeneralNames.class);
    }

    public void setFullName(GeneralNames fullName) {
        setChoiceValue(FULL_NAME, fullName);
    }

    public RelativeDistinguishedName getNameRelativeToCRLIssuer() {
        return getChoiceValueAs(NAME_RELATIVE_TO_CRL_ISSUER, RelativeDistinguishedName.class);
    }

    public void setNameRelativeToCrlIssuer(RelativeDistinguishedName nameRelativeToCrlIssuer) {
        setChoiceValue(NAME_RELATIVE_TO_CRL_ISSUER, nameRelativeToCrlIssuer);
    }
}
