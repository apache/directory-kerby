package org.haox.kerb.server.request;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.identity.KrbIdentity;
import org.haox.kerb.server.KdcConfig;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.KdcOption;
import org.haox.kerb.spec.type.kdc.KdcOptions;
import org.haox.kerb.spec.type.kdc.KdcRep;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;
import org.haox.kerb.spec.type.ticket.TicketFlag;
import org.haox.kerb.spec.type.ticket.TicketFlags;

import java.net.InetAddress;
import java.util.Date;
import java.util.List;

public abstract class KdcRequest {

    protected KdcContext kdcContext;

    private Ticket ticket;
    private boolean isPreAuthenticated;
    private KdcReq kdcReq;
    private KdcRep reply;
    private InetAddress clientAddress;
    private boolean isTcp;
    private EncryptionType encryptionType;
    private EncryptionKey clientKey;
    private KrbIdentity clientEntry;
    private KrbIdentity serverEntry;
    private EncryptionKey serverKey;
    private KrbIdentity tgsEntry;

    public KdcRequest(KdcReq kdcReq) {
        this.kdcReq = kdcReq;
    }

    public void setContext(KdcContext kdcContext) {
        this.kdcContext = kdcContext;
    }

    public void process() throws KrbException {
        checkVersion(kdcContext);
        checkClient(kdcContext);
        checkServer(kdcContext);
        preAuthenticate(kdcContext);
        authenticate(kdcContext);
        issueTicket(kdcContext);
        makeReply(kdcContext);
    }

    public KdcReq getKdcReq() {
        return kdcReq;
    }

    public KrbIdentity getTgsEntry() {
        return tgsEntry;
    }

    public void setTgsEntry(KrbIdentity tgsEntry) {
        this.tgsEntry = tgsEntry;
    }

    public boolean isTcp() {
        return isTcp;
    }

    public void isTcp(boolean isTcp) {
        this.isTcp = isTcp;
    }

    public KrbMessage getReply() {
        return reply;
    }

    public void setReply(KdcRep reply) {
        this.reply = reply;
    }

    public InetAddress getClientAddress() {
        return clientAddress;
    }

    public void setClientAddress(InetAddress clientAddress) {
        this.clientAddress = clientAddress;
    }

    public EncryptionType getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(EncryptionType encryptionType) {
        this.encryptionType = encryptionType;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public boolean isPreAuthenticated() {
        return isPreAuthenticated;
    }

    public void setPreAuthenticated(boolean isPreAuthenticated) {
        this.isPreAuthenticated = isPreAuthenticated;
    }

    public KrbIdentity getServerEntry() {
        return serverEntry;
    }

    public void setServerEntry(KrbIdentity serverEntry) {
        this.serverEntry = serverEntry;
    }

    public KrbIdentity getClientEntry() {
        return clientEntry;
    }

    public void setClientEntry(KrbIdentity clientEntry) {
        this.clientEntry = clientEntry;
    }

    public EncryptionKey getClientKey() {
        return clientKey;
    }

    public void setClientKey(EncryptionKey clientKey) {
        this.clientKey = clientKey;
    }

    public EncryptionKey getServerKey() {
        return serverKey;
    }

    public void setServerKey(EncryptionKey serverKey) {
        this.serverKey = serverKey;
    }

    public PrincipalName getTgsPrincipal() {
        PrincipalName result = new PrincipalName(kdcContext.getConfig().getTgsPrincipal());
        result.setRealm(kdcContext.getKdcRealm());
        return result;
    }

    protected abstract void makeReply(KdcContext kdcContext) throws KrbException;

    protected void checkVersion(KdcContext kdcContext) throws KrbException {
        KdcReq request = getKdcReq();

        int kerberosVersion = request.getPvno();
        if (kerberosVersion != KrbConstant.KRB_V5) {
            throw new KrbException(KrbErrorCode.KDC_ERR_BAD_PVNO);
        }
    }

    protected void checkPolicy(KdcContext kdcContext) throws KrbException {
        KrbIdentity entry = getClientEntry();

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
        KdcReq request = getKdcReq();

        PrincipalName clientPrincipal = request.getReqBody().getCname();
        String clientRealm = request.getReqBody().getRealm();
        if (clientRealm == null || clientRealm.isEmpty()) {
            clientRealm = kdcContext.getServerRealm();
        }
        clientPrincipal.setRealm(clientRealm);

        KrbIdentity clientEntry = getEntry(clientPrincipal.getName());
        setClientEntry(clientEntry);

        EncryptionType encType = request.getReqBody().getEtypes().listIterator().next();
        EncryptionKey clientKey = clientEntry.getKeys().get(encType);
        setClientKey(clientKey);
    }

    protected void preAuthenticate(KdcContext kdcContext) throws KrbException {
        KdcReq request = getKdcReq();

        PaData preAuthData = request.getPaData();

        if (kdcContext.getConfig().isPreauthRequired()) {
            if ((preAuthData == null) || (preAuthData.getElements().size() == 0)) {
                KrbError krbError = makePreAuthenticationError(kdcContext);
                throw new KrbErrorException(krbError);
            }
            List<PaDataEntry> paData = preAuthData.getElements();
            processPaData(kdcContext, paData);
        }

        setPreAuthenticated(true);
    }

    protected abstract void processPaData(KdcContext kdcContext, List<PaDataEntry> paData) throws KrbException;

    protected void checkTimestamp(KdcContext kdcContext, PaDataEntry paDataEntry) throws KrbException {
        EncryptionKey clientKey = getClientKey();

        EncryptedData dataValue = KrbCodec.decode(paDataEntry.getPaDataValue(), EncryptedData.class);
        PaEncTsEnc timestamp = EncryptionUtil.unseal(dataValue, clientKey,
                KeyUsage.AS_REQ_PA_ENC_TS, PaEncTsEnc.class);

        long clockSkew = kdcContext.getConfig().getAllowableClockSkew() * 1000;
        if (!timestamp.getAllTime().isInClockSkew(clockSkew)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED);
        }
    }

    protected void checkEncryptionType(KdcContext kdcContext) throws KrbException {
        List<EncryptionType> requestedTypes = getKdcReq().getReqBody().getEtypes();

        EncryptionType bestType = EncryptionUtil.getBestEncryptionType(requestedTypes,
                kdcContext.getConfig().getEncryptionTypes());

        if (bestType == null) {
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        setEncryptionType(bestType);
    }

    protected void authenticate(KdcContext requestContext) throws KrbException {
        checkEncryptionType(requestContext);
        checkPolicy(requestContext);
    }

    protected void issueTicket(KdcContext kdcContext) throws KrbException {
        KdcReq request = getKdcReq();

        EncryptionType encryptionType = getEncryptionType();
        EncryptionKey serverKey = getServerEntry().getKeys().get(encryptionType);

        PrincipalName ticketPrincipal = request.getReqBody().getSname();

        EncTicketPart encTicketPart = new EncTicketPart();
        KdcConfig config = kdcContext.getConfig();

        TicketFlags ticketFlags = new TicketFlags();
        encTicketPart.setFlags(ticketFlags);
        ticketFlags.setFlag(TicketFlag.INITIAL);

        if (isPreAuthenticated()) {
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

        EncryptionKey sessionKey = EncryptionHandler.random2Key(getEncryptionType());
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
        encTicketPart.setEndTime(krbEndTime);

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
        if (hostAddresses == null || hostAddresses.isEmpty()) {
            if (!config.isEmptyAddressesAllowed()) {
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }
        } else {
            encTicketPart.setClientAddresses(hostAddresses);
        }

        EncryptedData encryptedData = EncryptionUtil.seal(encTicketPart,
                serverKey, KeyUsage.KDC_REP_TICKET);

        Ticket newTicket = new Ticket();
        newTicket.setSname(ticketPrincipal);
        newTicket.setEncryptedEncPart(encryptedData);
        newTicket.setRealm(serverRealm);
        newTicket.setEncPart(encTicketPart);

        setTicket(newTicket);
    }

    private void checkServer(KdcContext kdcContext) throws KrbException {
        KdcReq request = getKdcReq();

        KrbIdentity tgsEntry = getEntry(getTgsPrincipal().getName());
        setTgsEntry(tgsEntry);

        PrincipalName principal = request.getReqBody().getSname();
        String serverRealm = request.getReqBody().getRealm();
        if (serverRealm == null || serverRealm.isEmpty()) {
            serverRealm = kdcContext.getServerRealm();
        }
        principal.setRealm(serverRealm);

        KrbIdentity serverEntry = getEntry(principal.getName());
        setServerEntry(serverEntry);

        EncryptionType encType = request.getReqBody().getEtypes().listIterator().next();
        EncryptionKey serverKey = serverEntry.getKeys().get(encType);
        setServerKey(serverKey);
    }

    protected KrbError makePreAuthenticationError(KdcContext kdcContext) throws KrbException {
        EncryptionType requestedType = getEncryptionType();
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
        methodData.getElements().add(new PaDataEntry(PaDataType.ENC_TIMESTAMP, null));
        if (!isNewEtype) {
            methodData.getElements().add(new PaDataEntry(PaDataType.ETYPE_INFO, encTypeInfo));
        }

        methodData.getElements().add(new PaDataEntry(PaDataType.ETYPE_INFO2, encTypeInfo2));

        KrbError krbError = new KrbError();
        krbError.setErrorCode(KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED);
        byte[] encodedData = KrbCodec.encode(methodData);
        krbError.setEdata(encodedData);
        return krbError;
    }

    protected KrbIdentity getEntry(String principal) throws KrbException {
        KrbIdentity entry = null;
        KrbErrorCode krbErrorCode = KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN;

        try {
            entry = kdcContext.getIdentityService().getIdentity(principal);
        } catch (Exception e) {
            throw new KrbException(krbErrorCode, e);
        }

        if (entry == null) {
            throw new KrbException(krbErrorCode);
        }

        return entry;
    }
}
