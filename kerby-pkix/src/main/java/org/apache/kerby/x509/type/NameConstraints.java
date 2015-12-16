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
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1SequenceType;

import static org.apache.kerby.x509.type.NameConstraints.MyEnum.*;

/*
 * NameConstraints ::= SEQUENCE {
 *     permittedSubtrees [0] GeneralSubtrees OPTIONAL,
 *     excludedSubtrees [1] GeneralSubtrees OPTIONAL
 * }
 */
public class NameConstraints extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        PERMITTED_SUBTREES,
        EXCLUDED_SUBTREES;

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
        new ExplicitField(PERMITTED_SUBTREES, GeneralSubtrees.class),
        new ExplicitField(EXCLUDED_SUBTREES, GeneralSubtrees.class)
    };

    public NameConstraints() {
        super(fieldInfos);
    }

    public GeneralSubtrees getPermittedSubtrees() {
        return getFieldAs(PERMITTED_SUBTREES, GeneralSubtrees.class);
    }

    public void setPermittedSubtrees(GeneralSubtrees permittedSubtrees) {
        setFieldAs(PERMITTED_SUBTREES, permittedSubtrees);
    }

    public GeneralSubtrees getExcludedSubtrees() {
        return getFieldAs(EXCLUDED_SUBTREES, GeneralSubtrees.class);
    }

    public void setExcludedSubtrees(GeneralSubtrees excludedSubtrees) {
        setFieldAs(EXCLUDED_SUBTREES, excludedSubtrees);
    }
}
