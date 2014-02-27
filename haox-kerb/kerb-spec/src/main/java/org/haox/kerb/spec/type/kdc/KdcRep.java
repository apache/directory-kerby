package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.ticket.Ticket;

import java.util.List;

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
public abstract class KdcRep extends KrbMessage {
    private List<PaData> paData;
    private String crealm;
    private PrincipalName cname;
    private Ticket ticket;
    private EncryptedData encryptedEncPart;
    private EncKdcRepPart encPart;

    public KdcRep(KrbMessageType msgType) {
        super(msgType);
    }

    public List<PaData> getPaData() {
        return paData;
    }

    public void setPaData(List<PaData> paData) {
        this.paData = paData;
    }

    public String getCrealm() {
        return crealm;
    }

    public void setCrealm(String crealm) {
        this.crealm = crealm;
    }

    public PrincipalName getCname() {
        return cname;
    }

    public void setCname(PrincipalName cname) {
        this.cname = cname;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public EncryptedData getEncryptedEncPart() {
        return encryptedEncPart;
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        this.encryptedEncPart = encryptedEncPart;
    }

    public EncKdcRepPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncKdcRepPart encPart) {
        this.encPart = encPart;
    }
}
