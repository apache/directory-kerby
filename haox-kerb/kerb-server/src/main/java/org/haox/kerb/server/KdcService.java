package org.haox.kerb.server;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.identity.IdentityService;
import org.haox.kerb.identity.KrbIdentity;
import org.haox.kerb.server.preauth.PaUtil;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.server.replay.ReplayCheckServiceImpl;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.*;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;
import org.haox.kerb.spec.type.ticket.TicketFlag;
import org.haox.kerb.spec.type.ticket.TicketFlags;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
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
        issueTicket(kdcContext);
        makeReply(kdcContext);
    }


    protected abstract void makeReply(KdcContext kdcContext) throws KrbException;

    protected void checkVersion(KdcContext kdcContext) throws KrbException {
        KdcReq request = kdcContext.getRequest();

        int kerberosVersion = request.getPvno();
        if (kerberosVersion != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KDC_ERR_BAD_PVNO);
        }
    }

    protected void checkPolicy(KdcContext kdcContext) throws KrbException {
        KrbIdentity entry = kdcContext.getClientEntry();

        if (entry.isDisabled()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }

        if (entry.isLocked()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }

        if (entry.getExpireTime().lessThan(new Date().getTime())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }
    }

    protected void checkClient(KdcContext kdcContext) throws KrbException {
        KdcReq request = kdcContext.getRequest();

        PrincipalName clientPrincipal = request.getReqBody().getCname();
        String clientRealm = request.getReqBody().getRealm();
        if (clientRealm == null || clientRealm.isEmpty()) {
            clientRealm = kdcContext.getServerRealm();
        }
        clientPrincipal.setRealm(clientRealm);

        KrbIdentity clientIdentity = getEntry(clientPrincipal.getName(),
                KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        kdcContext.setClientEntry(clientIdentity);
    }

    protected void preAuthenticate(KdcContext kdcContext) throws KrbException {
        KdcReq request = kdcContext.getRequest();

        KrbIdentity clientEntry = kdcContext.getClientEntry();

        EncryptionKey clientKey = null;

        PaData preAuthData = request.getPaData();

        if (kdcContext.getConfig().isPreauthRequired()) {
            if ((preAuthData == null) || (preAuthData.getElements().size() == 0)) {
                KrbError krbError = makePreAuthenticationError(kdcContext);
                throw new KrbErrorException(krbError);
            }
        }

        List<EncryptionType> requestedEncTypes = request.getReqBody().getEtypes();
        EncryptionType bestEncType = EncryptionUtil.getBestEncryptionType(requestedEncTypes,
                kdcContext.getConfig().getEncryptionTypes());
        if (bestEncType == null) {
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }
        clientKey = clientEntry.getKeys().get(bestEncType);
        kdcContext.setClientKey(clientKey);
        kdcContext.setPreAuthenticated(true);
    }

    protected void checkTimestamp(KdcContext kdcContext, PaDataEntry paDataEntry) throws KrbException {
        EncryptionKey clientKey = kdcContext.getClientKey();

        EncryptedData dataValue = KrbCodec.decode(paDataEntry.getPaDataValue(), EncryptedData.class);
        byte[] decryptedData = EncryptionHandler.decrypt(dataValue, clientKey,
                KeyUsage.AS_REQ_PA_ENC_TS);
        PaEncTsEnc timestamp = KrbCodec.decode(decryptedData, PaEncTsEnc.class);

        if (!timestamp.getPaTimestamp().isInClockSkew(kdcContext.getConfig().getAllowableClockSkew())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED);
        }
    }

    protected void checkEncryptionType(KdcContext kdcContext) throws KrbException {
        List<EncryptionType> requestedTypes = kdcContext.getRequest().getReqBody().getEtypes();

        EncryptionType bestType = EncryptionUtil.getBestEncryptionType(requestedTypes,
                kdcContext.getConfig().getEncryptionTypes());

        if (bestType == null) {
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        kdcContext.setEncryptionType(bestType);
    }

    protected void authenticate(KdcContext requestContext) throws KrbException {
        checkEncryptionType(requestContext);
        checkPolicy(requestContext);
    }

    protected void issueTicket(KdcContext kdcContext) throws KrbException {
        KdcReq request = kdcContext.getRequest();

        EncryptionType encryptionType = kdcContext.getEncryptionType();
        EncryptionKey serverKey = kdcContext.getServerEntry().getKeys().get(encryptionType);

        PrincipalName ticketPrincipal = request.getReqBody().getSname();

        EncTicketPart encTicketPart = new EncTicketPart();
        KdcConfig config = kdcContext.getConfig();

        TicketFlags ticketFlags = new TicketFlags();
        encTicketPart.setFlags(ticketFlags);
        ticketFlags.setFlag(TicketFlag.INITIAL);

        if (kdcContext.isPreAuthenticated()) {
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

        EncryptionKey sessionKey = EncryptionHandler.random2Key(kdcContext.getEncryptionType());
        encTicketPart.setKey(sessionKey);

        encTicketPart.setCname(request.getReqBody().getCname());
        encTicketPart.setCrealm(request.getReqBody().getRealm());

        TransitedEncoding transEnc = new TransitedEncoding();
        encTicketPart.setTransited(transEnc);
        String serverRealm = request.getReqBody().getRealm();

        KerberosTime now = KerberosTime.now();
        encTicketPart.setAuthTime(now);

        KerberosTime krbStartTime = request.getReqBody().getFrom();
        if (krbStartTime == null || krbStartTime.lessThan(now) ||
                krbStartTime.isInClockSkew(config.getAllowableClockSkew())) {
            krbStartTime = now;
        }
        if (krbStartTime.greaterThan(now)
                && !krbStartTime.isInClockSkew(config.getAllowableClockSkew())
                && !kdcOptions.isFlagSet(KdcOption.POSTDATED)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CANNOT_POSTDATE);
        }

        if (kdcOptions.isFlagSet(KdcOption.POSTDATED)) {
            if (!config.isPostdatedAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.POSTDATED);
            encTicketPart.setStartTime(krbStartTime);
        }

        KerberosTime krbEndTime = request.getReqBody().getTill();
        if (krbEndTime == null) {
            krbEndTime = krbStartTime.extend(config.getMaximumTicketLifetime() * 1000);
        } else if (krbStartTime.greaterThan(krbEndTime)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_NEVER_VALID);
        }

        long ticketLifeTime = Math.abs(krbEndTime.diff(krbStartTime));
        if (ticketLifeTime < config.getMinimumTicketLifetime()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_NEVER_VALID);
        }

        KerberosTime krbRtime = request.getReqBody().getRtime();
        if (kdcOptions.isFlagSet(KdcOption.RENEWABLE_OK)) {
            kdcOptions.setFlag(KdcOption.RENEWABLE);
        }
        if (kdcOptions.isFlagSet(KdcOption.RENEWABLE)) {
            if (!config.isRenewableAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.RENEWABLE);

            if (krbRtime == null) {
                krbRtime = KerberosTime.NEVER;
            }
            KerberosTime allowedMaximumRenewableTime = krbStartTime;
            allowedMaximumRenewableTime.extend(config.getMaximumRenewableLifetime() * 1000);
            if (krbRtime.greaterThan(allowedMaximumRenewableTime)) {
                krbRtime = allowedMaximumRenewableTime;
            }
            encTicketPart.setRenewtill(krbRtime);
        }

        HostAddresses hostAddresses = request.getReqBody().getAddresses();
        if (hostAddresses != null &&
                hostAddresses.getElements() != null &&
                hostAddresses.getElements().size() > 0) {
            encTicketPart.setClientAddresses(hostAddresses);
        } else if (!config.isEmptyAddressesAllowed()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
        }

        byte[] encoded = encTicketPart.encode();
        EncryptedData encryptedData = EncryptionHandler.encrypt(encoded,
                serverKey, KeyUsage.KDC_REP_TICKET);

        Ticket newTicket = new Ticket();
        newTicket.setSname(ticketPrincipal);
        newTicket.setEncryptedEncPart(encryptedData);
        newTicket.setRealm(serverRealm);
        newTicket.setEncPart(encTicketPart);

        kdcContext.setTicket(newTicket);
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

    private void checkServer(KdcContext kdcContext) throws KrbException {
        PrincipalName principal = kdcContext.getRequest().getReqBody().getSname();
        String serverRealm = kdcContext.getRequest().getReqBody().getRealm();
        if (serverRealm == null || serverRealm.isEmpty()) {
            serverRealm = kdcContext.getServerRealm();
        }
        principal.setRealm(serverRealm);

        kdcContext.setServerEntry(getEntry(principal.getName(),
                KrbErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN));
    }

    protected static KrbError makePreAuthenticationError(KdcContext kdcContext) throws KrbException {
        EncryptionType requestedType = kdcContext.getEncryptionType();
        List<EncryptionType> encryptionTypes = kdcContext.getConfig().getEncryptionTypes();
        boolean isNewEtype = true;

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
