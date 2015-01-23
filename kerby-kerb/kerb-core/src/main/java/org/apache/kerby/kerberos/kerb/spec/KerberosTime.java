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
package org.apache.kerby.kerberos.kerb.spec;

import org.apache.kerby.asn1.type.Asn1GeneralizedTime;

import java.util.Date;
import java.util.TimeZone;

/**
 KerberosTime    ::= GeneralizedTime -- with no fractional seconds
 */
public class KerberosTime extends Asn1GeneralizedTime {
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    public static final KerberosTime NEVER = new KerberosTime(Long.MAX_VALUE);

    public static final int MINUTE = 60000;

    public static final int DAY = MINUTE * 1440;

    public static final int WEEK = MINUTE * 10080;

    public KerberosTime() {
        super(0L);
    }

    /**
     * time in milliseconds
     */
    public KerberosTime(long time) {
        super(time);
    }

    /**
     * Return time in milliseconds
     */
    public long getTime() {
        if (getValue() != null) {
            return getValue().getTime();
        }
        return 0L;
    }

    /**
     * time in milliseconds
     */
    public void setTime(long time) {
        setValue(new Date(time));
    }

    public long getTimeInSeconds() {
        return getTime() / 1000;
    }

    public boolean lessThan(KerberosTime ktime) {
        return getValue().compareTo(ktime.getValue()) < 0;
    }

    public boolean lessThan(long time) {
        return getValue().getTime() <= time * 1000;
    }

    public boolean greaterThan(KerberosTime ktime) {
        return getValue().compareTo(ktime.getValue()) > 0;
    }

    /**
     * time in milliseconds
     */
    public boolean isInClockSkew(long clockSkew) {
        long delta = Math.abs(getTime() - System.currentTimeMillis());

        return delta < clockSkew;
    }

    public KerberosTime copy() {
        long time = getTime();
        KerberosTime result = new KerberosTime(time);
        return result;
    }

    /**
     * time in milliseconds
     */
    public KerberosTime extend(long duration) {
        long result = getTime() + duration;
        return new KerberosTime(result);
    }

    /**
     * Return diff time in milliseconds
     */
    public long diff(KerberosTime other) {
        return getTime() - other.getTime();
    }

    public static KerberosTime now() {
        return new KerberosTime(new Date().getTime());
    }
}
