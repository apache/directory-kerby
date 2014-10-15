package org.haox.kerb.spec.type;

import org.haox.asn1.type.Asn1GeneralizedTime;

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

    public long getTimeInSeconds() {
        return getTime() / 1000;
    }

    public boolean lessThan(KerberosTime ktime) {
        return getValue().compareTo(ktime.getValue()) == -1;
    }

    public boolean lessThan(long time) {
        return getValue().getTime() <= time * 1000;
    }

    public boolean greaterThan(KerberosTime ktime) {
        return getValue().compareTo(ktime.getValue()) == 1;
    }

    public boolean isInClockSkew(long clockSkew) {
        // The KerberosTime does not have milliseconds
        long delta = Math.abs(getValue().getTime() - System.currentTimeMillis());

        return delta < clockSkew;
    }

    public static KerberosTime now() {
        return new KerberosTime(new Date().getTime());
    }
}
