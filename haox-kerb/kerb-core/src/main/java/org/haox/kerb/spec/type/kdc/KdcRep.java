package org.haox.kerb.spec.type.kdc;

import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1Tag;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.Ticket;

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
public class KdcRep extends AbstractKrbMessage {
    private static int PADATA = 2;
    private static int CREALM = 3;
    private static int CNAME = 4;
    private static int TICKET = 5;
    private static int ENC_PART = 6;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(PVNO, 0, Asn1Integer.class),
            new Asn1Tag(MSG_TYPE, 1, Asn1Integer.class),
            new Asn1Tag(PADATA, 2, PaData.class),
            new Asn1Tag(CREALM, 3, KerberosString.class),
            new Asn1Tag(CNAME, 4, PrincipalName.class),
            new Asn1Tag(TICKET, 5, Ticket.class),
            new Asn1Tag(ENC_PART, 6, EncryptedData.class)
    };

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    private EncKdcRepPart encPart;

    public KdcRep(KrbMessageType msgType) throws KrbException {
        super(msgType);
    }

    public PaData getPaData() throws KrbException {
        return getFieldAs(PADATA, PaData.class);
    }

    public void setPaData(PaData paData) throws KrbException {
        setFieldAs(PADATA, paData);
    }

    public PrincipalName getCname() throws KrbException {
        return getFieldAs(CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName sname) throws KrbException {
        setFieldAs(CNAME, sname);
    }

    public String getCrealm() throws KrbException {
        return getFieldAsString(CREALM);
    }

    public void setCrealm(String realm) throws KrbException {
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
