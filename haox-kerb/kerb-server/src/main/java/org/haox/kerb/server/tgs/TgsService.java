package org.haox.kerb.server.tgs;

import org.apache.directory.shared.kerberos.codec.options.ApOptions;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.KdcService;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.EncKdcRepPart;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;

import java.util.List;

public class TgsService extends KdcService {

    @Override
    protected void processPaData(KdcContext kdcContext, List<PaDataEntry> paData) throws KrbException {
        PaDataType pdType;
        for (PaDataEntry pd : paData) {
            pdType = pd.getPaDataType();
            if (pdType == PaDataType.TGS_REQ) {
                checkAuthenticator(kdcContext, pd);
            } else if (pdType == PaDataType.ENC_TIMESTAMP) {
                checkTimestamp(kdcContext, pd);
            }
        }

        kdcContext.setPreAuthenticated(true);
    }

    private void checkAuthenticator(KdcContext kdcContext, PaDataEntry paDataEntry) throws KrbException {
        ApReq authHeader = KrbCodec.decode(paDataEntry.getPaDataValue(), ApReq.class);

        if (authHeader.getPvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        if (authHeader.getMsgType() != KrbMessageType.AP_REP) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MSG_TYPE);
        }

        if (authHeader.getTicket().getTktvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        EncryptionKey ticketKey = null;

        if (authHeader.getApOptions().isFlagSet(0/*ApOptions.USE_SESSION_KEY*/)) {
            ticketKey = authHeader.getTicket().getEncPart().getKey();
        } else {
            //ticketKey = serverKey;
        }

        if (ticketKey == null) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_NOKEY);
        }

        Ticket ticket = null; // todo
        byte[] encTicketPartData = EncryptionHandler.decrypt(ticket.getEncryptedEncPart(),
                ticketKey, KeyUsage.KDC_REP_TICKET);
        EncTicketPart encPart = KrbCodec.decode(encTicketPartData, EncTicketPart.class);
        ticket.setEncPart(encPart);

        byte[] authenticatorData = EncryptionHandler.decrypt(authHeader.getEncryptedAuthenticator(),
                ticket.getEncPart().getKey(), KeyUsage.TGS_REQ_AUTH); // ?

        Authenticator authenticator = KrbCodec.decode(authenticatorData, Authenticator.class);

        if (!authenticator.getCname().equals(ticket.getEncPart().getCname())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADMATCH);
        }

        if (ticket.getEncPart().getClientAddresses() != null) {
            HostAddress tmp = new HostAddress();
            tmp.setAddress(kdcContext.getClientAddress().getAddress());
            if (!ticket.getEncPart().getClientAddresses().getElements().contains(tmp)) {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
            }
        } else if (! kdcContext.getConfig().isEmptyAddressesAllowed()) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
        }

        PrincipalName serverPrincipal = ticket.getSname();
        serverPrincipal.setRealm(ticket.getRealm());
        PrincipalName clientPrincipal = authenticator.getCname();
        clientPrincipal.setRealm(authenticator.getCrealm());
        KerberosTime clientTime = authenticator.getCtime();
        int clientMicroSeconds = authenticator.getCusec();

        if (!authenticator.getCtime().isInClockSkew(
                kdcContext.getConfig().getAllowableClockSkew())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_SKEW);
        }

        KerberosTime startTime = (ticket.getEncPart().getStartTime() != null) ? ticket.getEncPart()
                .getStartTime() : ticket.getEncPart().getAuthTime();

        KerberosTime now = new KerberosTime();
        boolean isValidStartTime = startTime.lessThan(now);

        if (!isValidStartTime || (ticket.getEncPart().getFlags().isInvalid())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_NYV);
        }

        if (!ticket.getEncPart().getEndTime().greaterThan(now)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED);
        }

        authHeader.getApOptions().setFlag(ApOptions.MUTUAL_REQUIRED);
    }

    @Override
    protected void makeReply(KdcContext kdcContext) throws KrbException {
        Ticket ticket = kdcContext.getTicket();

        TgsRep reply = new TgsRep();

        reply.setCname(kdcContext.getClientEntry().getPrincipal());
        reply.setCrealm(kdcContext.getServerRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart(kdcContext);
        reply.setEncPart(encKdcRepPart);

        EncryptionKey clientKey = kdcContext.getClientKey();
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
                clientKey, KeyUsage.TGS_REP_ENCPART_SESSKEY);
        reply.setEncryptedEncPart(encryptedData);

        kdcContext.setReply(reply);
    }
}
