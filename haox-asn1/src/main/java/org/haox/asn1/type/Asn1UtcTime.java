package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.UniversalTag;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

public class Asn1UtcTime extends AbstractAsn1Simple<Long>
{
    public Asn1UtcTime() {
        this(null);
    }

    public Asn1UtcTime(Long time) {
        super(UniversalTag.UTC_TIME, time);
    }

    protected void toValue() throws IOException {
        String dateStr = new String(getBytes(), StandardCharsets.US_ASCII);
        String nomalizedStr;
        SimpleDateFormat sdf;

        sdf = new SimpleDateFormat("yyyyMMddHHmmssz");
        sdf.setTimeZone(new SimpleTimeZone(0, "Z"));

        if (dateStr.indexOf('-') < 0 && dateStr.indexOf('+') < 0) {
            if (dateStr.length() == 11) {
                nomalizedStr = dateStr.substring(0, 10) + "00GMT+00:00";
            }
            else {
                nomalizedStr = dateStr.substring(0, 12) + "GMT+00:00";
            }
        }  else {
            int index = dateStr.indexOf('-');
            if (index < 0) {
                index = dateStr.indexOf('+');
            }
            nomalizedStr = dateStr;

            if (index == dateStr.length() - 3) {
                nomalizedStr += "00";
            }

            if (index == 10) {
                nomalizedStr =  nomalizedStr.substring(0, 10) + "00GMT" + nomalizedStr.substring(10, 13) + ":" + nomalizedStr.substring(13, 15);
            } else {
                nomalizedStr =  nomalizedStr.substring(0, 12) + "GMT" + nomalizedStr.substring(12, 15) + ":" +  nomalizedStr.substring(15, 17);
            }
        }

        try {
            setValue(sdf.parse(nomalizedStr).getTime());
        } catch (ParseException e) {
            throw new IOException("Failed to parse as date time");
        }
    }

    @Override
    protected void toBytes(EncodingOption encodingOption) {
        Date date = new Date(getValue());
        SimpleDateFormat dateF = new SimpleDateFormat("yyMMddHHmmss'Z'");
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
