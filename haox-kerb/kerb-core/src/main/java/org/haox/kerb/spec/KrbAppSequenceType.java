package org.haox.kerb.spec;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.TaggingSequence;

/**
 * This is for application specific sequence tagged with a number.
 */
public abstract class KrbAppSequenceType extends TaggingSequence {
    public KrbAppSequenceType(int tagNo, Asn1FieldInfo[] fieldInfos) {
        super(tagNo, fieldInfos, true);
    }

    protected int getFieldAsInt(int index) {
        Integer value = getFieldAsInteger(index);
        if (value != null) {
            return value.intValue();
        }
        return -1;
    }

    protected void setFieldAsString(int index, String value) {
        setFieldAs(index, new KerberosString(value));
    }

    protected KerberosTime getFieldAsTime(int index) {
        KerberosTime value = getFieldAs(index, KerberosTime.class);
        return value;
    }

    protected void setFieldAsTime(int index, long value) {
        setFieldAs(index, new KerberosTime(value));
    }

    protected void setField(int index, KrbEnum krbEnum) {
        setFieldAsInt(index, krbEnum.getValue());
    }
}
