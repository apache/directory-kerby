package org.haox.kerb.server.tgs;

import org.apache.directory.shared.kerberos.codec.options.ApOptions;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.KdcService;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.*;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;
import org.haox.kerb.spec.type.ticket.TicketFlag;

import java.util.List;

public class TgsService extends KdcService {

    @Override
    protected void processPaData(KdcContext kdcContext, List<PaDataEntry> paData) throws KrbException {
        PaDataType pdType;
        for (PaDataEntry pd : paData) {
            pdType = pd.getPaDataType();
            if (pdType == PaDataType.TGS_REQ) {
                checkAuthenticator((TgsContext) kdcContext, pd);
            } else if (pdType == PaDataType.ENC_TIMESTAMP) {
                checkTimestamp(kdcContext, pd);
            }
        }

        kdcContext.setPreAuthenticated(true);
    }

    private void checkAuthenticator(TgsContext kdcContext, PaDataEntry paDataEntry) throws KrbException {
        ApReq authHeader = KrbCodec.decode(paDataEntry.getPaDataValue(), ApReq.class);

        if (authHeader.getPvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        if (authHeader.getMsgType() != KrbMessageType.AP_REQ) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MSG_TYPE);
        }

        EncryptionType encType = kdcContext.getRequest().getReqBody().getEtypes().listIterator().next();
        EncryptionKey tgsKey = kdcContext.getTgsEntry().getKeys().get(encType);

        Ticket ticket = authHeader.getTicket();
        if (ticket.getTktvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        EncTicketPart encPart = EncryptionUtil.unseal(ticket.getEncryptedEncPart(),
                tgsKey, KeyUsage.KDC_REP_TICKET, EncTicketPart.class);
        ticket.setEncPart(encPart);

        EncryptionKey encKey = null;
        //if (authHeader.getApOptions().isFlagSet(ApOptions.USE_SESSION_KEY)) {
        encKey = ticket.getEncPart().getKey();

        if (encKey == null) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_NOKEY);
        }
        Authenticator authenticator = EncryptionUtil.unseal(authHeader.getEncryptedAuthenticator(),
                encKey, KeyUsage.TGS_REQ_AUTH, Authenticator.class);

        if (!authenticator.getCname().equals(ticket.getEncPart().getCname())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADMATCH);
        }

        if (ticket.getEncPart().getClientAddresses() != null) {
            HostAddress tmp = new HostAddress();
            tmp.setAddress(kdcContext.getClientAddress().getAddress());
            if (!ticket.getEncPart().getClientAddresses().getElements().contains(tmp)) {
                //throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
            }
        } else if (! kdcContext.getConfig().isEmptyAddressesAllowed()) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
        }

        PrincipalName serverPrincipal = ticket.getSname();
        serverPrincipal.setRealm(ticket.getRealm());
        PrincipalName clientPrincipal = authenticator.getCname();
        clientPrincipal.setRealm(authenticator.getCrealm());

        if (!authenticator.getCtime().isInClockSkew(
                kdcContext.getConfig().getAllowableClockSkew())) {
            //throw new KrbException(KrbErrorCode.KRB_AP_ERR_SKEW);
        }

        KerberosTime startTime = (ticket.getEncPart().getStartTime() != null) ? ticket.getEncPart()
                .getStartTime() : ticket.getEncPart().getAuthTime();

        KerberosTime now = new KerberosTime();
        boolean isValidStartTime = startTime.lessThan(now);

        if (!isValidStartTime || (ticket.getEncPart().getFlags().isInvalid())) {
            //throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_NYV);
        }

        if (!ticket.getEncPart().getEndTime().greaterThan(now)) {
            //throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED);
        }

        authHeader.getApOptions().setFlag(ApOptions.MUTUAL_REQUIRED);

        kdcContext.setTgtSessionKey(ticket.getEncPart().getKey());
    }

    @Override
    protected void makeReply(KdcContext kdcContext) throws KrbException {
        TgsContext tgsContext = (TgsContext) kdcContext;

        Ticket ticket = kdcContext.getTicket();

        TgsRep reply = new TgsRep();

        reply.setCname(kdcContext.getClientEntry().getPrincipal());
        reply.setCrealm(kdcContext.getServerRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart(kdcContext);
        reply.setEncPart(encKdcRepPart);

        EncryptionKey sessionKey = tgsContext.getTgtSessionKey();
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
                sessionKey, KeyUsage.TGS_REP_ENCPART_SESSKEY);
        reply.setEncryptedEncPart(encryptedData);

        kdcContext.setReply(reply);
    }

    protected EncKdcRepPart makeEncKdcRepPart(KdcContext kdcContext) {
        KdcReq request = kdcContext.getRequest();
        Ticket ticket = kdcContext.getTicket();

        EncKdcRepPart encKdcRepPart = new EncTgsRepPart();

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
