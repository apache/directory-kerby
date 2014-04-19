package org.haox.kerb.spec.type;

import org.haox.asn1.type.Asn1GeneralizedTime;

import java.util.TimeZone;

/**
 KerberosTime    ::= GeneralizedTime -- with no fractional seconds
 */
public class KerberosTime extends Asn1GeneralizedTime {
    private static final TimeZone UTC = TimeZone.getTimeZone( "UTC" );

    public static final KerberosTime NEVER = new KerberosTime( Long.MAX_VALUE );

    /** The number of milliseconds in a minute. */
    public static final int MINUTE = 60000;

    /** The number of milliseconds in a day. */
    public static final int DAY = MINUTE * 1440;

    /** The number of milliseconds in a week. */
    public static final int WEEK = MINUTE * 10080;

    public KerberosTime() {
        super();
    }

    public KerberosTime(Long time) {
        super(time);
    }

    public boolean lessThan( KerberosTime ktime ) {
        return getValue() <= ktime.getValue();
    }

    public boolean lessThan(long time ) {
        return getValue() <= time;
    }

    public boolean greaterThan( KerberosTime ktime ) {
        return getValue() > ktime.getValue();
    }

    public boolean isInClockSkew( long clockSkew ) {
        // The KerberosTime does not have milliseconds
        long delta = Math.abs( getValue() - System.currentTimeMillis() );

        return delta < clockSkew;
    }
}
