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

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.ExplicitField;

/**
 *
 * Ref. RFC 3280.
 * <pre>
 *       GeneralSubtree ::= SEQUENCE {
 *         base                    GeneralName,
 *         minimum         [0]     BaseDistance DEFAULT 0,
 *         maximum         [1]     BaseDistance OPTIONAL 
 *       }
 * </pre>
 * 
 */
public class GeneralSubtree extends Asn1SequenceType {
    private static final int BASE = 0;
    private static final int MINIMUM = 1;
    private static final int MAXMUM = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(BASE, GeneralName.class),
        new ExplicitField(MINIMUM, 0, Asn1Integer.class),
        new ExplicitField(MAXMUM, 1, Asn1Integer.class)
    };

    public GeneralSubtree() {
        super(fieldInfos);
    }

    public GeneralName getBase() {
        return getFieldAs(BASE, GeneralName.class);
    }

    public void setBase(GeneralName base) {
        setFieldAs(BASE, base);
    }

    public int getMinimum() {
        return getFieldAsInteger(MINIMUM);
    }

    public void setMinimum(int minimum) {
        setFieldAsInt(MINIMUM, minimum);
    }

    public int getMaximum() {
        return getFieldAsInteger(MAXMUM);
    }

    public void setMaxmum(int maxmum) {
        setFieldAsInt(MAXMUM, maxmum);
    }
}
