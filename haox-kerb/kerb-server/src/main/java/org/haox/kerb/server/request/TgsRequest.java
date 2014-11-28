package org.haox.kerb.server.request;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.ap.ApOption;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.*;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;
import org.haox.kerb.spec.type.ticket.TicketFlag;

import java.nio.ByteBuffer;

public class TgsRequest extends KdcRequest {

    private EncryptionKey tgtSessionKey;

    public TgsRequest(TgsReq tgsReq) {
        super(tgsReq);
    }

    public EncryptionKey getTgtSessionKey() {
        return tgtSessionKey;
    }

    public void setTgtSessionKey(EncryptionKey tgtSessionKey) {
        this.tgtSessionKey = tgtSessionKey;
    }

    @Override
    protected void processPaData(PaData paData) throws KrbException {
        PaDataType pdType;
        for (PaDataEntry pd : paData.getElements()) {
            pdType = pd.getPaDataType();
            if (pdType == PaDataType.TGS_REQ) {
                checkAuthenticator(kdcContext, pd);
            }
        }

        super.processPaData(paData);
    }

    private void checkAuthenticator(KdcContext kdcContext, PaDataEntry paDataEntry) throws KrbException {
        ApReq authHeader = KrbCodec.decode(paDataEntry.getPaDataValue(), ApReq.class);

        if (authHeader.getPvno() != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        if (authHeader.getMsgType() != KrbMessageType.AP_REQ) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MSG_TYPE);
        }

        EncryptionType encType = getKdcReq().getReqBody().getEtypes().listIterator().next();
        EncryptionKey tgsKey = getTgsEntry().getKeys().get(encType);

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

        HostAddresses hostAddresses = ticket.getEncPart().getClientAddresses();
        if (hostAddresses == null || hostAddresses.isEmpty()) {
            if (!kdcContext.getConfig().isEmptyAddressesAllowed()) {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
            }
        } else if (!hostAddresses.contains(getClientAddress())) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
        }

        PrincipalName serverPrincipal = ticket.getSname();
        serverPrincipal.setRealm(ticket.getRealm());
        PrincipalName clientPrincipal = authenticator.getCname();
        clientPrincipal.setRealm(authenticator.getCrealm());

        if (!authenticator.getCtime().isInClockSkew(
                kdcContext.getConfig().getAllowableClockSkew() * 1000)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_SKEW);
        }

        KerberosTime now = KerberosTime.now();
        KerberosTime startTime = ticket.getEncPart().getStartTime();
        if (startTime == null) {
            startTime = ticket.getEncPart().getAuthTime();
        }
        if (! startTime.lessThan(now)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_NYV);
        }

        KerberosTime endTime = ticket.getEncPart().getEndTime();
        if (! endTime.greaterThan(now)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED);
        }

        authHeader.getApOptions().setFlag(ApOption.MUTUAL_REQUIRED);

        setTgtSessionKey(ticket.getEncPart().getKey());
    }

    @Override
    protected void makeReply() throws KrbException {
        Ticket ticket = getTicket();

        TgsRep reply = new TgsRep();

        reply.setCname(getClientEntry().getPrincipal());
        reply.setCrealm(kdcContext.getServerRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = makeEncKdcRepPart();
        reply.setEncPart(encKdcRepPart);

        EncryptionKey sessionKey = getTgtSessionKey();
        EncryptedData encryptedData = EncryptionUtil.seal(encKdcRepPart,
                sessionKey, KeyUsage.TGS_REP_ENCPART_SESSKEY);
        reply.setEncryptedEncPart(encryptedData);

        setReply(reply);
    }

    private EncKdcRepPart makeEncKdcRepPart() {
        KdcReq request = getKdcReq();
        Ticket ticket = getTicket();

        EncKdcRepPart encKdcRepPart = new EncTgsRepPart();

        //session key
        encKdcRepPart.setKey(ticket.getEncPart().getKey());

        LastReq lastReq = new LastReq();
        LastReqEntry entry = new LastReqEntry();
        entry.setLrType(LastReqType.THE_LAST_INITIAL);
        entry.setLrValue(new KerberosTime());
        lastReq.add(entry);
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

    public ByteBuffer getRequestBody() throws KrbException {
        return null;
    }

    public EncryptionKey getArmorKey() throws KrbException {
        return null;
    }
}
