package org.haox.kerb.server;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.server.as.AsContext;
import org.haox.kerb.identity.Identity;
import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.identity.KrbIdentity;
import org.haox.kerb.server.preauth.PaUtil;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.server.replay.ReplayCheckServiceImpl;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.*;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;
import org.haox.kerb.spec.type.ticket.TicketFlag;
import org.haox.kerb.spec.type.ticket.TicketFlags;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.net.InetAddress;
import java.util.List;

public abstract class KdcService {
    private static final Logger logger = LoggerFactory.getLogger(KdcService.class);

    protected IdentityService identityService;
    protected ReplayCheckService replayCheckService;

    public KdcService() {
        this.replayCheckService = new ReplayCheckServiceImpl();
    }

    public void setIdentityService(IdentityService identityService) {
        this.identityService = identityService;
    }

    public void serve(KdcContext kdcContext) throws KrbException {
        checkVersion(kdcContext);
        checkClient(kdcContext);
        checkServer(kdcContext);
        preAuthenticate(kdcContext);
        authenticate(kdcContext);
        KdcRep reply = makeReply(kdcContext);
        issueTicket(kdcContext);
        kdcContext.setReply(reply);
    }

    protected void checkVersion(KdcContext kdcContext) throws KrbException {
        KdcReq request = kdcContext.getRequest();

        int kerberosVersion = request.getPvno();
        if (kerberosVersion != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KDC_ERR_BAD_PVNO);
        }
    }

    protected void checkClient(KdcContext kdcContext) throws KrbException {
        KdcReq request = kdcContext.getRequest();

        String clientPrincipal = request.getReqBody().getCname().getName();
        KrbIdentity clientIdentity = getEntry(clientPrincipal,
                KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        kdcContext.setClientEntry((KrbIdentity) clientIdentity);
    }

    protected abstract void preAuthenticate(KdcContext kdcContext) throws KrbException;
    protected abstract void authenticate(KdcContext kdcContext) throws KrbException;

    protected void issueTicket(KdcContext authContext) throws KrbException {
        KdcReq request = authContext.getRequest();

        PrincipalName serverPrincipal = request.getReqBody().getSname();

        EncryptionType encryptionType = authContext.getEncryptionType();
        EncryptionKey serverKey = null;//authContext.checkServer().getAttributes().get(encryptionType);

        PrincipalName ticketPrincipal = request.getReqBody().getSname();

        EncTicketPart encTicketPart = new EncTicketPart();
        KdcConfig config = authContext.getConfig();

        TicketFlags ticketFlags = new TicketFlags();
        encTicketPart.setFlags(ticketFlags);
        ticketFlags.setFlag(TicketFlag.INITIAL);

        if (authContext.isPreAuthenticated()) {
            ticketFlags.setFlag(TicketFlag.PRE_AUTH);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.FORWARDABLE)) {
            if (!config.isForwardableAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.FORWARDABLE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.PROXIABLE)) {
            if (!config.isProxiableAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.PROXIABLE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.ALLOW_POSTDATE)) {
            if (!config.isPostdatedAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.MAY_POSTDATE);
        }

        KdcOptions kdcOptions = request.getReqBody().getKdcOptions();

        EncryptionKey sessionKey = EncryptionHandler.makeRandomKey(authContext.getEncryptionType());
        encTicketPart.setKey(sessionKey);

        encTicketPart.setCname(request.getReqBody().getCname());
        encTicketPart.setCrealm(request.getReqBody().getRealm());

        TransitedEncoding transEnc = new TransitedEncoding();
        encTicketPart.setTransited(transEnc);
        String serverRealm = request.getReqBody().getRealm();

        KerberosTime now = new KerberosTime();

        encTicketPart.setAuthTime(now);

        KerberosTime startTime = request.getReqBody().getFrom();

        if (startTime == null || startTime.lessThan(now) || startTime.isInClockSkew(config.getAllowableClockSkew())
                && !request.getReqBody().getKdcOptions().isFlagSet(KdcOption.POSTDATED)) {
            startTime = now;
        }

        if ((startTime != null) && startTime.greaterThan(now)
                && !startTime.isInClockSkew(config.getAllowableClockSkew())
                && !request.getReqBody().getKdcOptions().isFlagSet(KdcOption.POSTDATED)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CANNOT_POSTDATE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.POSTDATED)) {
            if (!config.isPostdatedAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.POSTDATED);
            ticketFlags.setFlag(TicketFlag.INVALID);
            encTicketPart.setStartTime(startTime);
        }

        long till = 0;

        if (request.getReqBody().getTill() == null) {
            till = Long.MAX_VALUE;
        } else {
            till = request.getReqBody().getTill().getTimeInSeconds();
        }

        long endTime = Math.min(till, startTime.getTimeInSeconds() + config.getMaximumTicketLifetime());
        KerberosTime kerberosEndTime = new KerberosTime(endTime);
        encTicketPart.setEndTime(kerberosEndTime);

        if (kerberosEndTime.lessThan(startTime)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_NEVER_VALID);
        }

        long ticketLifeTime = Math.abs(startTime.getTimeInSeconds() - kerberosEndTime.getTimeInSeconds());

        if (ticketLifeTime < config.getMinimumTicketLifetime()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_NEVER_VALID);
        }

        KerberosTime tempRtime = request.getReqBody().getRtime();

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.RENEWABLE_OK)
                && request.getReqBody().getTill().greaterThan(kerberosEndTime)) {
            if (!config.isRenewableAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            request.getReqBody().getKdcOptions().setFlag(KdcOption.RENEWABLE);
            tempRtime = request.getReqBody().getTill();
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.RENEWABLE)) {
            if (!config.isRenewableAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.RENEWABLE);

            if (tempRtime == null || tempRtime.getTimeInSeconds() == 0) {
                tempRtime = KerberosTime.NEVER;
            }

            long renewTill = Math.min(tempRtime.getTimeInSeconds(),
                    startTime.getTimeInSeconds() + config.getMaximumRenewableLifetime());
            encTicketPart.setRenewtill(new KerberosTime(renewTill));
        }

        if (request.getReqBody().getAddresses() != null
                && request.getReqBody().getAddresses().getElements() != null
                && request.getReqBody().getAddresses().getElements().size() > 0) {
            encTicketPart.setClientAddresses(request.getReqBody().getAddresses());
        }
        else {
            if (!config.isEmptyAddressesAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }
        }

        EncryptedData encryptedData = EncryptionHandler.seal(encTicketPart, serverKey,
                KeyUsage.KDC_REP_TICKET);

        Ticket newTicket = new Ticket();
        newTicket.setSname(ticketPrincipal);
        newTicket.setEncryptedEncPart(encryptedData);
        newTicket.setRealm(serverRealm);
        newTicket.setEncPart(encTicketPart);

        authContext.setTicket(newTicket);
    }

    protected KdcRep makeReply(KdcContext kdcContext) throws KrbException {
        KdcReq request = kdcContext.getRequest();

        AsContext asContext = (AsContext) kdcContext;
        Ticket ticket = asContext.getTicket();

        AsRep reply = new AsRep();

        reply.setCname(request.getReqBody().getCname());
        reply.setCrealm(request.getReqBody().getRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        //session key
        encKdcRepPart.setKey(ticket.getEncPart().getKey());

        LastReq lastReq = new LastReq();
        LastReqEntry entry = new LastReqEntry();
        entry.setLrType(LastReqType.THE_LAST_INITIAL);
        entry.setLrValue(new KerberosTime());
        lastReq.getElements().add(entry);
        encKdcRepPart.setLastReq(lastReq);
        // TODO - resp.key-expiration := client.expiration; requires identity

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

        EncAsRepPart encAsRepPart = new EncAsRepPart();

        logContext(asContext);
        logReply(reply, encKdcRepPart);

        EncryptionKey clientKey = asContext.getClientKey();
        EncryptedData encryptedData = EncryptionHandler.seal(encAsRepPart, clientKey,
                KeyUsage.AS_REP_ENCPART);
        reply.setEncryptedEncPart(encryptedData);

        reply.setEncPart(encKdcRepPart);

        return reply;
    }

    private void checkServer(KdcContext kdcContext) throws KrbException {
        PrincipalName principal = kdcContext.getRequest().getReqBody().getSname();

        String principalWithRealm = principal.getName() + "@"
                + kdcContext.getRequest().getReqBody().getRealm();
        kdcContext.setServerEntry(getEntry(principalWithRealm,
                KrbErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN));
    }
    
    protected static void logContext(KdcContext kdcContext) {
        long clockSkew = kdcContext.getConfig().getAllowableClockSkew();
        InetAddress clientAddress = kdcContext.getClientAddress();

        StringBuilder sb = new StringBuilder();

        sb.append("Logging " + " context:");

        sb.append("\n\t" + "clockSkew              " + clockSkew);
        sb.append("\n\t" + "clientAddress          " + clientAddress);

        PrincipalName clientPrincipal = kdcContext.getClientEntry().getPrincipal();
        KrbIdentity clientEntry = kdcContext.getClientEntry();

        sb.append("\n\t" + "principal              " + clientPrincipal);
        sb.append("\n\t" + "principal              " + clientEntry.getPrincipal());

        PrincipalName serverPrincipal = kdcContext.getRequest().getReqBody().getSname();
        KrbIdentity serverEntry = kdcContext.getServerEntry();

        sb.append("\n\t" + "principal              " + serverPrincipal);
        sb.append("\n\t" + "principal              " + serverEntry.getPrincipal());

        EncryptionType encryptionType = kdcContext.getEncryptionType();
        int clientKeyVersion = 0;//clientEntry.getKeys().get(encryptionType).getKeyVersion();
        int serverKeyVersion = 0;//serverEntry.getKeys().get(encryptionType).getKeyVersion();
        sb.append("\n\t" + "Request key type       " + encryptionType);
        sb.append("\n\t" + "Client key version     " + clientKeyVersion);
        sb.append("\n\t" + "Server key version     " + serverKeyVersion);

        String message = sb.toString();

        logger.debug(message);
    }


    protected static void logReply(KdcRep reply, EncKdcRepPart part) {
        StringBuffer sb = new StringBuffer();

        sb.append("Responding with " + " reply:");
        sb.append("\n\t" + "messageType:           " + reply.getMsgType());
        sb.append("\n\t" + "protocolVersionNumber: " + reply.getPvno());
        sb.append("\n\t" + "nonce:                 " + part.getNonce());
        sb.append("\n\t" + "clientPrincipal:       " + reply.getCname());
        sb.append("\n\t" + "client realm:          " + reply.getCrealm());
        sb.append("\n\t" + "serverPrincipal:       " + part.getSname());
        sb.append("\n\t" + "server realm:          " + part.getSrealm());
        sb.append("\n\t" + "auth time:             " + part.getAuthTime());
        sb.append("\n\t" + "start time:            " + part.getStartTime());
        sb.append("\n\t" + "end time:              " + part.getEndTime());
        sb.append("\n\t" + "renew-till time:       " + part.getRenewTill());
        sb.append("\n\t" + "hostAddresses:         " + part.getCaddr());

        String message = sb.toString();

        logger.debug(message);
    }

    protected static KrbError makePreAuthenticationError(KdcContext kdcContext) throws KrbException {
        EncryptionType requestedType = kdcContext.getEncryptionType();
        List<EncryptionType> encryptionTypes = kdcContext.getDefaultEtypes();
        boolean isNewEtype = true;//EncryptionHandler.isNewEncryptionType(requestedType);

        EtypeInfo2 eTypeInfo2 = new EtypeInfo2();

        EtypeInfo eTypeInfo = new EtypeInfo();

        for (EncryptionType encryptionType : encryptionTypes) {
            if (!isNewEtype) {
                EtypeInfoEntry etypeInfoEntry = new EtypeInfoEntry();
                etypeInfoEntry.setEtype(encryptionType);
                etypeInfoEntry.setSalt(null);
                eTypeInfo.getElements().add(etypeInfoEntry);
            }

            EtypeInfo2Entry etypeInfo2Entry = new EtypeInfo2Entry();
            etypeInfo2Entry.setEtype(encryptionType);
            eTypeInfo2.getElements().add(etypeInfo2Entry);
        }

        byte[] encTypeInfo = null;
        byte[] encTypeInfo2 = null;
        if (!isNewEtype) {
            encTypeInfo = KrbCodec.encode(eTypeInfo);
        }
        encTypeInfo2 = KrbCodec.encode(eTypeInfo2);

        MethodData methodData = new MethodData();
        methodData.getElements().add(PaUtil.createPaDataEntry(PaDataType.ENC_TIMESTAMP, null));
        if (!isNewEtype) {
            methodData.getElements().add(PaUtil.createPaDataEntry(PaDataType.ETYPE_INFO, encTypeInfo));
        }

        methodData.getElements().add(PaUtil.createPaDataEntry(PaDataType.ETYPE_INFO2, encTypeInfo2));

        KrbError krbError = new KrbError();
        krbError.setErrorCode(KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED);
        byte[] encodedData = KrbCodec.encode(methodData);
        krbError.setEdata(encodedData);
        return krbError;
    }

    protected KrbIdentity getEntry(String principal, KrbErrorCode KrbErrorCode) throws KrbException {
        KrbIdentity entry = null;

        try {
            entry = identityService.getIdentity(principal);
        } catch (Exception e) {
            throw new KrbException(KrbErrorCode, e);
        }

        if (entry == null) {
            throw new KrbException(KrbErrorCode);
        }

        return entry;
    }
}
