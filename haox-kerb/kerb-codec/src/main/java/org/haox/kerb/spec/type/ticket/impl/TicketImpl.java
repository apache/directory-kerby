package org.haox.kerb.spec.type.ticket.impl;

import org.haox.kerb.codec.AbstractSequenceType;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbString;
import org.haox.kerb.spec.type.KrbTag;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;

public class TicketImpl  extends AbstractSequenceType implements Ticket {
    private EncTicketPart encPart;

    public int getTktvno() throws KrbException {
        KrbInteger value = getFieldAs(Tag.TKT_VNO, KrbInteger.class);
        if (value != null) {
            return value.getValue().intValue();
        }
        return -1;
    }

    public String getSname() throws KrbException {
        KrbString value = getFieldAs(Tag.SNAME, KrbString.class);
        if (value != null) {
            return value.getValue();
        }
        return null;
    }

    public void setSname(String sname) throws KrbException {
        setField(Tag.SNAME, KrbTypes.makeString(sname));
    }

    public String getRealm() throws KrbException {
        KrbString value = getFieldAs(Tag.REALM, KrbString.class);
        if (value != null) {
            return value.getValue();
        }
        return null;
    }

    public void setRealm(String realm) throws KrbException {
        setField(Tag.REALM, KrbTypes.makeString(realm));
    }

    public EncryptedData getEncryptedEncPart() throws KrbException {
        return getFieldAs(Tag.ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) throws KrbException {
        setField(Tag.ENC_PART, encryptedEncPart);
    }

    public EncTicketPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncTicketPart encPart) {
        this.encPart = encPart;
    }

    @Override
    public KrbTag[] getTags() {
        return Tag.values();
    }
}
