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

import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.ExplicitField;

/**
 * Ref. RFC 3281
 * <pre>
 *     Target  ::= CHOICE {
 *       targetName          [0] GeneralName,
 *       targetGroup         [1] GeneralName,
 *       targetCert          [2] TargetCert
 *     }
 * </pre>
 */
public class Target extends Asn1Choice {
    private static final int TARGET_NAME = 0;
    private static final int TARGET_GROUP = 1;
    private static final int TARGET_CERT = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new ExplicitField(TARGET_NAME, GeneralName.class),
        new ExplicitField(TARGET_GROUP, GeneralName.class),
        new ExplicitField(TARGET_CERT, TargetCert.class),
    };

    public Target() {
        super(fieldInfos);
    }

    public GeneralName getTargetName() {
        return getFieldAs(TARGET_NAME, GeneralName.class);
    }

    public void setTargetName(GeneralName targetName) {
        setFieldAs(TARGET_NAME, targetName);
    }

    public GeneralName getTargetGroup() {
        return getFieldAs(TARGET_GROUP, GeneralName.class);
    }

    public void setTargetGroup(GeneralName targetGroup) {
        setFieldAs(TARGET_GROUP, targetGroup);
    }

    public TargetCert targetCert() {
        return getFieldAs(TARGET_CERT, TargetCert.class);
    }

    public void setTargetCert(TargetCert targetCert) {
        setFieldAs(TARGET_CERT, targetCert);
    }
}
