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
 *
 * <pre>
 *  AttCertIssuer ::= CHOICE {
 *       v1Form   GeneralNames,  -- MUST NOT be used in this profile
 *       v2Form   [0] V2Form     -- v2 only
 *  }
 * </pre>
 */
public class AttCertIssuer extends Asn1Choice {
    private static final int V1_FORM = 0;
    private static final int V2_FORM = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(V1_FORM, GeneralNames.class),
        new ExplicitField(V2_FORM, 0, V2Form.class)
    };

    public AttCertIssuer() {
        super(fieldInfos);
    }

    public GeneralNames getV1Form() {
        return getFieldAs(V1_FORM, GeneralNames.class);
    }

    public void setV1Form(GeneralNames v1Form) {
        setFieldAs(V1_FORM, v1Form);
    }

    public V2Form getV2Form() {
        return getFieldAs(V2_FORM, V2Form.class);
    }

    public void setV2Form(V2Form v2Form) {
        setFieldAs(V2_FORM, v2Form);
    }
}
