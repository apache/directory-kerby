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
package org.apache.kerby.x500.type;

import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1FieldInfo;

/**
 *
 * <pre>
 *     Name ::= CHOICE { RDNSequence }
 * </pre>
 */
public class Name extends Asn1Choice {
    private static final int RDN_SEQUENCE = 0;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
        new Asn1FieldInfo(RDN_SEQUENCE, RDNSequence.class),
    };

    public Name() {
        super(fieldInfos);
    }

    public RDNSequence getName() {
        return getFieldAs(RDN_SEQUENCE, RDNSequence.class);
    }

    public void setName(RDNSequence name) {
        setFieldAs(RDN_SEQUENCE, name);
    }
}
