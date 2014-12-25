package org.haox.kerb.spec.kdc;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.KerberosString;
import org.haox.kerb.spec.common.EncryptedData;
import org.haox.kerb.spec.common.KrbMessage;
import org.haox.kerb.spec.common.KrbMessageType;
import org.haox.kerb.spec.common.PrincipalName;
import org.haox.kerb.spec.pa.PaData;
import org.haox.kerb.spec.ticket.Ticket;

/**
 KDC-REP         ::= SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
 padata          [2] SEQUENCE OF PA-DATA OPTIONAL
 -- NOTE: not empty --,
 crealm          [3] Realm,
 cname           [4] PrincipalName,
 ticket          [5] Ticket,
 enc-part        [6] EncryptedData
 -- EncASRepPart or EncTGSRepPart,
 -- as appropriate
 }
 */
public class KdcRep extends KrbMessage {
    private static int PADATA = 2;
    private static int CREALM = 3;
    private static int CNAME = 4;
    private static int TICKET = 5;
    private static int ENC_PART = 6;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PVNO, Asn1Integer.class),
            new Asn1FieldInfo(MSG_TYPE, Asn1Integer.class),
            new Asn1FieldInfo(PADATA, PaData.class),
            new Asn1FieldInfo(CREALM, KerberosString.class),
            new Asn1FieldInfo(CNAME, PrincipalName.class),
            new Asn1FieldInfo(TICKET, Ticket.class),
            new Asn1FieldInfo(ENC_PART, EncryptedData.class)
    };

    private EncKdcRepPart encPart;

    public KdcRep(KrbMessageType msgType) {
        super(msgType, fieldInfos);
    }

    public PaData getPaData() {
        return getFieldAs(PADATA, PaData.class);
    }

    public void setPaData(PaData paData) {
        setFieldAs(PADATA, paData);
    }

    public PrincipalName getCname() {
        return getFieldAs(CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName sname) {
        setFieldAs(CNAME, sname);
    }

    public String getCrealm() {
        return getFieldAsString(CREALM);
    }

    public void setCrealm(String realm) {
        setFieldAs(CREALM, new KerberosString(realm));
    }

    public Ticket getTicket() {
        return getFieldAs(TICKET, Ticket.class);
    }

    public void setTicket(Ticket ticket) {
        setFieldAs(TICKET, ticket);
    }

    public EncryptedData getEncryptedEncPart() {
        return getFieldAs(ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        setFieldAs(ENC_PART, encryptedEncPart);
    }

    public EncKdcRepPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncKdcRepPart encPart) {
        this.encPart = encPart;
    }
}
