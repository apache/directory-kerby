package org.haox.asn1.type;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

public class Asn1GeneralizedTime extends AbstractAsn1Primitive<Long>
{
    public Asn1GeneralizedTime() {
        this(0L);
    }

    public Asn1GeneralizedTime(Long time) {
        super(time, BerTag.GENERALIZED_TIME);
    }

    protected void toValue() throws IOException {
        String dateStr = new String(getBytes(), StandardCharsets.US_ASCII);
        SimpleDateFormat sdf;
        String d = dateStr;

        if (dateStr.endsWith("Z")) {
            if (hasFractionalSeconds(dateStr)) {
                sdf = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
            } else {
                sdf = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
            }

            sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        }
        else if (dateStr.indexOf('-') > 0 || dateStr.indexOf('+') > 0) {
            d = normalizeTimeString(dateStr);
            if (hasFractionalSeconds(dateStr)) {
                sdf = new SimpleDateFormat("yyyyMMddHHmmss.SSSz");
            } else {
                sdf = new SimpleDateFormat("yyyyMMddHHmmssz");
            }

            sdf.setTimeZone(new SimpleTimeZone(0, "Z"));
        } else {
            if (hasFractionalSeconds(dateStr)) {
                sdf = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
            } else {
                sdf = new SimpleDateFormat("yyyyMMddHHmmss");
            }

            sdf.setTimeZone(new SimpleTimeZone(0, TimeZone.getDefault().getID()));
        }

        if (hasFractionalSeconds(dateStr)) {
            // java misinterprets extra digits as being milliseconds...
            String frac = d.substring(14);
            int index;
            for (index = 1; index < frac.length(); index++) {
                char ch = frac.charAt(index);
                if (!('0' <= ch && ch <= '9')) {
                    break;        
                }
            }

            if (index - 1 > 3) {
                frac = frac.substring(0, 4) + frac.substring(index);
                d = d.substring(0, 14) + frac;
            } else if (index - 1 == 1) {
                frac = frac.substring(0, index) + "00" + frac.substring(index);
                d = d.substring(0, 14) + frac;
            } else if (index - 1 == 2) {
                frac = frac.substring(0, index) + "0" + frac.substring(index);
                d = d.substring(0, 14) + frac;
            }
        }

        try {
            setValue(sdf.parse(d).getTime());
        } catch (ParseException e) {
            throw new IOException("Failed to parse as date time");
        }
    }

    @Override
    protected void toBytes() {
        Date date = new Date(getValue());
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        dateF.setTimeZone(new SimpleTimeZone(0, "Z"));

        String str = dateF.format(date);
        byte[] bytes = str.getBytes(StandardCharsets.US_ASCII);
        setBytes(bytes);
    }

    private boolean hasFractionalSeconds(String dateStr) {
        for (int i = 0; i != dateStr.length(); i++) {
            if (dateStr.charAt(i) == '.') {
                if (i == 14) {
                    return true;
                }
            }
        }
        return false;
    }

    private String normalizeTimeString(String stime) {
        if (stime.charAt(stime.length() - 1) == 'Z') {
            return stime.substring(0, stime.length() - 1) + "GMT+00:00";
        } else {
            int signPos = stime.length() - 5;
            char sign = stime.charAt(signPos);
            if (sign == '-' || sign == '+') {
                return stime.substring(0, signPos)
                        + "GMT"
                        + stime.substring(signPos, signPos + 3)
                        + ":"
                        + stime.substring(signPos + 3);
            } else {
                signPos = stime.length() - 3;
                sign = stime.charAt(signPos);
                if (sign == '-' || sign == '+') {
                    return stime.substring(0, signPos)
                            + "GMT"
                            + stime.substring(signPos)
                            + ":00";
                }
            }
        }
        return stime + calculateGMTOffset();
    }

    private String calculateGMTOffset() {
        String sign = "+";
        TimeZone timeZone = TimeZone.getDefault();
        int offset = timeZone.getRawOffset();
        if (offset < 0) {
            sign = "-";
            offset = -offset;
        }
        int hours = offset / (60 * 60 * 1000);
        int minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);

        if (timeZone.useDaylightTime() && timeZone.inDaylightTime(new Date(getValue()))) {
            hours += sign.equals("+") ? 1 : -1;
        }

        return "GMT" + sign + convert(hours) + ":" + convert(minutes);
    }

    private String convert(int time) {
        if (time < 10) {
            return "0" + time;
        }

        return Integer.toString(time);
    }
}
