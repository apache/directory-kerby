package org.apache.kerberos.kerb.spec;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1SequenceType;

public abstract class KrbSequenceType extends Asn1SequenceType {

    public KrbSequenceType(Asn1FieldInfo[] fieldInfos) {
        super(fieldInfos);
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

    protected void setField(int index, KrbEnum value) {
        setFieldAsInt(index, value.getValue());
    }
}
