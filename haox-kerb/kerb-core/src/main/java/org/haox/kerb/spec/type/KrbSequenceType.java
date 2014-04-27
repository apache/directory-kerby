package org.haox.kerb.spec.type;

import org.haox.asn1.Asn1Tag;
import org.haox.asn1.type.SequenceType;

public abstract class KrbSequenceType extends SequenceType {

    public KrbSequenceType(Asn1Tag[] tags) {
        super(tags);
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
