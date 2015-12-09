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
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.ExplicitField;
import static org.apache.kerby.x509.type.RoleSyntax.MyEnum.*;

/**
 *Ref. RFC3281
 * <pre>
 * RoleSyntax ::= SEQUENCE {
 *                 roleAuthority  [0] GeneralNames OPTIONAL,
 *                 roleName       [1] GeneralName
 *           } 
 * </pre>
 */
public class RoleSyntax extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        ROLE_AUTHORITY,
        ROLE_NAME;

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
        new ExplicitField(ROLE_AUTHORITY, GeneralNames.class),
        new ExplicitField(ROLE_NAME, GeneralName.class)
    };

    public RoleSyntax() {
        super(fieldInfos);
    }

    public GeneralNames getRoleAuthority() {
        return getFieldAs(ROLE_AUTHORITY, GeneralNames.class);
    }

    public void setRoleAuthority(GeneralNames roleAuthority) {
        setFieldAs(ROLE_AUTHORITY, roleAuthority);
    }

    public GeneralName getRoleName() {
        return getFieldAs(ROLE_NAME, GeneralName.class);
    }

    public void setRoleName(GeneralName roleName) {
        setFieldAs(ROLE_NAME, roleName);
    }
}
