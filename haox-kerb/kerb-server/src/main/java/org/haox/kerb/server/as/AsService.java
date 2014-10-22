package org.haox.kerb.server.as;

import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.KdcService;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.EncAsRepPart;
import org.haox.kerb.spec.type.kdc.EncKdcRepPart;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.ticket.Ticket;
import org.haox.kerb.spec.type.ticket.TicketFlag;

import java.util.List;

public class AsService extends KdcService {

    @Override
    protected void processPaData(KdcContext kdcContext, List<PaDataEntry> paData) throws KrbException {
        PaDataType pdType;
        for (PaDataEntry pd : paData) {
            pdType = pd.getPaDataType();
            if (pdType == PaDataType.ENC_TIMESTAMP) {
                checkTimestamp(kdcContext, pd);
            }
        }

        kdcContext.setPreAuthenticated(true);
    }

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

    protected EncKdcRepPart makeEncKdcRepPart(KdcContext kdcContext) {
        KdcReq request = kdcContext.getRequest();
        Ticket ticket = kdcContext.getTicket();

        EncKdcRepPart encKdcRepPart = new EncAsRepPart();

        //session key
        encKdcRepPart.setKey(ticket.getEncPart().getKey());

        LastReq lastReq = new LastReq();
        LastReqEntry entry = new LastReqEntry();
        entry.setLrType(LastReqType.THE_LAST_INITIAL);
        entry.setLrValue(new KerberosTime());
        lastReq.getElements().add(entry);
        encKdcRepPart.setLastReq(lastReq);

        encKdcRepPart.setNonce(request.getReqBody().getNonce());

        encKdcRepPart.setFlags(ticket.getEncPart().getFlags());
        encKdcRepPart.setAuthTime(ticket.getEncPart().getAuthTime());
        encKdcRepPart.setStartTime(ticket.getEncPart().getStartTime());
        encKdcRepPart.setEndTime(ticket.getEncPart().getEndTime());

        if (ticket.getEncPart().getFlags().isFlagSet(TicketFlag.RENEWABLE)) {
            encKdcRepPart.setRenewTill(ticket.getEncPart().getRenewtill());
        }

        encKdcRepPart.setSname(ticket.getSname());
        encKdcRepPart.setSrealm(ticket.getRealm());
        encKdcRepPart.setCaddr(ticket.getEncPart().getClientAddresses());

        return encKdcRepPart;
    }
}
