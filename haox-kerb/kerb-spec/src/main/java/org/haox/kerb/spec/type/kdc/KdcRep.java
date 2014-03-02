package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.PaData;
import org.haox.kerb.spec.type.common.PrincipalName;
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
public interface KdcRep extends KrbMessage {
    public List<PaData> getPaData();

    public void setPaData(List<PaData> paData);

    public String getCrealm();

    public void setCrealm(String crealm);

    public PrincipalName getCname();

    public void setCname(PrincipalName cname);

    public Ticket getTicket();

    public void setTicket(Ticket ticket);

    public EncryptedData getEncryptedEncPart();

    public void setEncryptedEncPart(EncryptedData encryptedEncPart);

    public EncKdcRepPart getEncPart();

    public void setEncPart(EncKdcRepPart encPart);
}
