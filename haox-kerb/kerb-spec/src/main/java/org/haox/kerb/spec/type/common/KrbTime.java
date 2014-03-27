package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;

import java.util.TimeZone;

public class KrbTime implements KrbType {
    private static final TimeZone UTC = TimeZone.getTimeZone( "UTC" );

    private String date;

    public static final KrbTime NEVER = new KrbTime( Long.MAX_VALUE );

    /** The number of milliseconds in a minute. */
    public static final int MINUTE = 60000;

    /** The number of milliseconds in a day. */
    public static final int DAY = MINUTE * 1440;

    /** The number of milliseconds in a week. */
    public static final int WEEK = MINUTE * 10080;

    private long value;

    public KrbTime() {
        this.value = 0L;
    }

    public KrbTime(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }

    public void setValue(long value) {
        this.value = value;
    }

    public boolean lessThan( KrbTime ktime ) {
        return value <= ktime.value;
    }

    public boolean lessThan(long time ) {
        return value <= time;
    }

    public boolean greaterThan( KrbTime ktime ) {
        return value > ktime.value;
    }

    public boolean isInClockSkew( long clockSkew ) {
        // The KerberosTime does not have milliseconds
        long delta = Math.abs( value - System.currentTimeMillis() );

        return delta < clockSkew;
    }
}
