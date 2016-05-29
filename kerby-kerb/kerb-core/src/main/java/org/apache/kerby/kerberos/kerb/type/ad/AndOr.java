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
package org.apache.kerby.kerberos.kerb.type.ad;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * <pre>
 * AD-AND-OR               ::= SEQUENCE {
 *         condition-count [0] Int32,
 *         elements        [1] AuthorizationData
 * }
 * </pre>
 * 
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class AndOr extends KrbSequenceType {

    protected enum AndOrField implements EnumType {
        AndOr_ConditionCount, AndOr_Elements;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    /** The CamMac's fields */
    private static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(AndOrField.AndOr_ConditionCount, Asn1Integer.class),
            new ExplicitField(AndOrField.AndOr_Elements, AuthorizationData.class)};

    public AndOr() {
        super(fieldInfos);
    }

    public AndOr(int conditionCount, AuthorizationData authzData) {
        super(fieldInfos);
        setFieldAs(AndOrField.AndOr_ConditionCount, new Asn1Integer(conditionCount));
        setFieldAs(AndOrField.AndOr_Elements, authzData);
    }

    public int getConditionCount() {
        return getFieldAs(AndOrField.AndOr_ConditionCount, Asn1Integer.class).getValue().intValue();
    }

    public void setConditionCount(int conditionCount) {
        setFieldAs(AndOrField.AndOr_ConditionCount, new Asn1Integer(conditionCount));
    }

    public AuthorizationData getAuthzData() {
        return getFieldAs(AndOrField.AndOr_Elements, AuthorizationData.class);
    }

    public void setAuthzData(AuthorizationData authzData) {
        setFieldAs(AndOrField.AndOr_Elements, authzData);
    }

}
