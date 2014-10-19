package org.haox.kerb.server.as;

import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.KdcService;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.EncKdcRepPart;
import org.haox.kerb.spec.type.ticket.Ticket;

public class AsService extends KdcService {

    @Override
    protected void makeReply(KdcContext kdcContext) throws KrbException {
        Ticket ticket = kdcContext.getTicket();

        AsRep reply = new AsRep();

        reply.setCname(kdcContext.getClientEntry().getPrincipal());
        reply.setCrealm(kdcContext.getServerRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart(kdcContext);
        reply.setEncPart(encKdcRepPart);

        EncryptionKey clientKey = kdcContext.getClientKey();
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
                clientKey, KeyUsage.AS_REP_ENCPART);
        reply.setEncryptedEncPart(encryptedData);

        kdcContext.setReply(reply);
    }
}
