/*
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
package org.apache.kerby.kerberos.kerb.type;

import java.util.Date;

import org.apache.kerby.asn1.type.Asn1GeneralizedTime;

/**
 * A specialization of the ASN.1 GeneralTime. The Kerberos time contains date and
 * time up to the seconds, but with no fractional seconds. It's also always
 * expressed as UTC timeZone, thus the 'Z' at the end of its string representation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class KerberosTime extends Asn1GeneralizedTime {

    /** Constant for the {@link KerberosTime} "infinity." */
    public static final KerberosTime NEVER = new KerberosTime(Long.MAX_VALUE);

    /** The number of milliseconds in a minute. */
    public static final int MINUTE = 60000;

    /** The number of milliseconds in a day. */
    public static final int DAY = MINUTE * 1440;

    /** The number of milliseconds in a week. */
    public static final int WEEK = MINUTE * 10080;

    /**
     * Creates a new instance of a KerberosTime object with the current time
     */
    public KerberosTime() {
        // divide current time by 1000 to drop the ms then multiply by 1000 to convert to ms
        super((System.currentTimeMillis() / 1000L) * 1000L); 
    }

    /**
     * @param time in milliseconds
     */
    public KerberosTime(long time) {
        super(time);
    }

    /**
     * @return time in milliseconds
     */
    public long getTime() {
        return getValue().getTime();
    }

    /**
     * Set the Kerberos time
     * @param time set time in milliseconds
     */
    public void setTime(long time) {
        setValue(new Date(time));
    }

    /**
     * Gets the time in seconds
     * 
     * @return The time
     */
    public long getTimeInSeconds() {
        return getTime() / 1000;
    }

    /**
     * Compare the KerberosTime with another one, and return <tt>true</tt>
     * if it's lesser than the provided one
     * 
     * @param ktime in milliseconds
     * @return <tt>true</tt> if less
     */
    public boolean lessThan(KerberosTime ktime) {
        return getValue().compareTo(ktime.getValue()) < 0;
    }

    /**
     * Compare the KerberosTime with a time, and return <tt>true</tt>
     * if it's lesser than the provided one
     * 
     * @param time in milliseconds
     * @return <tt>true</tt> if less
     */
    public boolean lessThan(long time) {
        return getValue().getTime() < time;
    }

    /**
     * Compare the KerberosTime with another one, and return <tt>true</tt>
     * if it's greater than the provided one
     * 
     * @param ktime compare with milliseconds
     * @return <tt>true</tt> if greater
     */
    public boolean greaterThan(KerberosTime ktime) {
        return getValue().compareTo(ktime.getValue()) > 0;
    }

    /**
     * Check if the KerberosTime is within the provided clock skew
     * 
     * @param clockSkew The clock skew
     * @return true if in clock skew
     */
    public boolean isInClockSkew(long clockSkew) {
        long delta = Math.abs(getTime() - System.currentTimeMillis());

        return delta < clockSkew;
    }

    /**
     * @return A copy of the KerbeorsTime
     */
    public KerberosTime copy() {
        long time = getTime();
        
        return new KerberosTime(time);
    }

    /**
     * Create a KerberosTime based on a time in milliseconds.
     * 
     * @param duration The duration
     * @return The created kerberos time
     */
    public KerberosTime extend(long duration) {
        long result = getTime() + duration;
        
        return new KerberosTime(result);
    }

    /**
     * Return the difference between the currentKerberosTime and the provided one
     * 
     * @param kerberosTime The kerberos time
     * @return The difference between the two KerberosTime
     */
    public long diff(KerberosTime kerberosTime) {
        return getTime() - kerberosTime.getTime();
    }

    /**
     * @return The current KerberosTime
     */
    public static KerberosTime now() {
        return new KerberosTime(System.currentTimeMillis());
    }

    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode() {
        return getValue().hashCode();
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        
        if (!(that instanceof KerberosTime)) {
            return false;
        }
        
        return this.getValue().equals(((KerberosTime) that).getValue());
    }
}