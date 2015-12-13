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
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1GeneralizedTime;
import org.apache.kerby.asn1.type.Asn1UtcTime;

import java.util.Date;

import static org.apache.kerby.x509.type.Time.MyEnum.GENERAL_TIME;
import static org.apache.kerby.x509.type.Time.MyEnum.UTC_TIME;

/**
 *
 * <pre>
 * Time ::= CHOICE {
 *             utcTime        UTCTime,
 *             generalTime    GeneralizedTime
 *          }
 * </pre>
 */
public class Time extends Asn1Choice {
    protected enum MyEnum implements EnumType {
        UTC_TIME,
        GENERAL_TIME;

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
        new Asn1FieldInfo(UTC_TIME, Asn1UtcTime.class),
        new Asn1FieldInfo(GENERAL_TIME, Asn1GeneralizedTime.class)
    };

    public Time() {
        super(fieldInfos);
    }

    public Date getUtcTime() {
        return getChoiceValueAs(UTC_TIME, Asn1UtcTime.class).getValue();
    }

    public void setUtcTime(Asn1UtcTime utcTime) {
        setChoiceValue(UTC_TIME, utcTime);
    }

    public Date generalizedTime() {
        return getChoiceValueAs(GENERAL_TIME, Asn1GeneralizedTime.class).getValue();
    }

    public void setGeneralTime(Asn1GeneralizedTime generalTime) {
        setChoiceValue(GENERAL_TIME, generalTime);
    }
}
