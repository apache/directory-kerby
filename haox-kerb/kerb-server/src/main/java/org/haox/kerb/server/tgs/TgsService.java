package org.haox.kerb.server.tgs;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.server.KdcConfig;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.KdcService;
import org.haox.kerb.server.identity.KrbIdentity;
import org.haox.kerb.server.replay.ReplayCheckService;
import org.haox.kerb.spec.KrbConstant;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.ap.ApOptions;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.ap.Authenticator;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;
import org.haox.kerb.spec.type.ticket.EncTicketPart;
import org.haox.kerb.spec.type.ticket.Ticket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Date;
import java.util.List;

public class TgsService extends KdcService {
    private static final Logger logger = LoggerFactory.getLogger(TgsService.class);

    private static final String SERVICE_NAME = "Ticket Granting Service (TGS)";

    private void selectEncryptionType(TgsContext authContext) throws KrbException {
        KdcContext kdcContext = authContext;
        KdcConfig config = kdcContext.getConfig();

        List<EncryptionType> requestedTypes = kdcContext.getRequest().getReqBody().getEtypes();
        logger.debug("Encryption types requested by client {}.", requestedTypes);

        EncryptionType bestType = EncryptionHandler.getBestEncryptionType(requestedTypes, kdcContext.getDefaultEtypes());

        logger.debug("Session will use encryption type {}.", bestType);

        if (bestType == null) {
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        kdcContext.setEncryptionType(bestType);
    }

    private static void checkPolicy(TgsContext authContext) throws KrbException {
        KrbIdentity entry = authContext.getClientEntry();

        if (entry.isDisabled()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }

        if (entry.isLockedOut()) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }

        if (entry.getExpiration().lessThan(new Date().getTime())) {
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }
    }

    private void verifyEncryptedTimestamp(TgsContext authContext) throws KrbException {
        logger.debug("Verifying using encrypted timestamp.");

        KdcConfig config = authContext.getConfig();
        KdcReq request = authContext.getRequest();
        KrbIdentity clientEntry = authContext.getClientEntry();
        String clientName = clientEntry.getPrincipal().getName();

        EncryptionKey clientKey = null;

        EncryptionType encryptionType = authContext.getEncryptionType();
        clientKey = clientEntry.getKeyMap().get(encryptionType);

        if (clientKey == null) {
            throw new KrbException(KrbErrorCode.KDC_ERR_NULL_KEY);
        }

        if (config.isPaEncTimestampRequired()) {
            PaData preAuthData = request.getPaData();

            if (preAuthData == null) {
                throw new KrbErrorException(makePreAuthenticationError(authContext));
            }

            PaEncTsEnc timestamp = null;

            for (PaDataEntry paData : preAuthData.getElements()) {
                if (paData.getPaDataType().equals(PaDataType.ENC_TIMESTAMP)) {
                    EncryptedData dataValue = KrbCodec.decode(paData.getPaDataValue(), EncryptedData.class);
                    byte[] decryptedData = EncryptionHandler.decrypt(dataValue, clientKey,
                            KeyUsage.AS_REQ_PA_ENC_TS);
                    timestamp = KrbCodec.decode(decryptedData, PaEncTsEnc.class);
                }
            }

            if (timestamp == null) {
                throw new KrbErrorException(makePreAuthenticationError(authContext));
            }

            if (!timestamp.getPaTimestamp().isInClockSkew(config.getAllowableClockSkew())) {
                throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED);
            }
        }

        authContext.setClientKey(clientKey);
    }

    @Override
    protected void preAuthenticate(KdcContext requestContext, KdcReq request) throws KrbException {
        TgsContext authnContext = (TgsContext) requestContext;

        KdcConfig config = authnContext.getConfig();

        KrbIdentity clientEntry = authnContext.getClientEntry();
        String clientName = clientEntry.getPrincipal().getName();

        EncryptionKey clientKey = null;

        PaData preAuthData = request.getPaData();

        if ((preAuthData == null) || (preAuthData.getElements().size() == 0)) {
            KrbError krbError = makePreAuthenticationError(authnContext);
            throw new KrbErrorException(krbError);
        }

        authnContext.setClientKey(clientKey);
        authnContext.setPreAuthenticated(true);
    }

    @Override
    protected void authenticate(KdcContext requestContext, KdcReq request) throws KrbException {
        TgsContext authnContext = (TgsContext) requestContext;

        selectEncryptionType(authnContext);
        getClientEntry(authnContext);
        checkPolicy(authnContext);
    }

    public static Authenticator verifyAuthHeader(ApReq authHeader, Ticket ticket, EncryptionKey serverKey,
                                                 long clockSkew, ReplayCheckService replayCache,
                                                 boolean emptyAddressesAllowed, InetAddress clientAddress,
                                                 KeyUsage authenticatorKeyUsage, boolean isValidate) throws KrbException, KrbException {
        if (authHeader.getPvno() != KrbConstant.KRB_V5)
        {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        if (authHeader.getMsgType() != KrbMessageType.AP_REP)
        {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_MSG_TYPE);
        }

        if (authHeader.getTicket().getTktvno() != KrbConstant.KRB_V5)
        {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADVERSION);
        }

        EncryptionKey ticketKey = null;

        if (authHeader.getApOptions().isFlagSet(0/*ApOptions.USE_SESSION_KEY*/))
        {
            ticketKey = authHeader.getTicket().getEncPart().getKey();
        }
        else
        {
            ticketKey = serverKey;
        }

        if (ticketKey == null) {

            throw new KrbException(KrbErrorCode.KRB_AP_ERR_NOKEY);
        }

        byte[] encTicketPartData = EncryptionHandler.decrypt(ticket.getEncryptedEncPart(), ticketKey,
                KeyUsage.KDC_REP_TICKET);
        EncTicketPart encPart = KrbCodec.decode(encTicketPartData, EncTicketPart.class);
        ticket.setEncPart(encPart);

        byte[] authenticatorData = EncryptionHandler.decrypt(authHeader.getEncryptedAuthenticator(),
                ticket.getEncPart().getKey(), authenticatorKeyUsage);

        Authenticator authenticator = KrbCodec.decode(authenticatorData, Authenticator.class);

        if (!authenticator.getCname().getName().equals(ticket.getEncPart().getCname().getName()))
        {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADMATCH);
        }

        if (ticket.getEncPart().getClientAddresses() != null)
        {
            HostAddress tmp = new HostAddress();
            tmp.setAddress(clientAddress.getAddress());
            if (!ticket.getEncPart().getClientAddresses().getElements().contains(tmp))
            {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
            }
        }
        else
        {
            if (!emptyAddressesAllowed)
            {
                throw new KrbException(KrbErrorCode.KRB_AP_ERR_BADADDR);
            }
        }

        PrincipalName serverPrincipal = null;//getKerberosPrincipal(ticket.getSname(), ticket.getRealm());
        PrincipalName clientPrincipal = null;//getKerberosPrincipal(authenticator.getCname(), authenticator.getCrealm());
        KerberosTime clientTime = authenticator.getCtime();
        int clientMicroSeconds = authenticator.getCusec();

        if (replayCache.checkReplay(clientPrincipal.toString(), serverPrincipal.toString() ,
                clientTime.getTimeInSeconds(), clientMicroSeconds)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_REPEAT);
        }

        if (!authenticator.getCtime().isInClockSkew(clockSkew))
        {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_SKEW);
        }

        /*
         * "The server computes the age of the ticket: local (server) time minus
         * the starttime inside the Ticket.  If the starttime is later than the
         * current time by more than the allowable clock skew, or if the INVALID
         * flag is set in the ticket, the KRB_AP_ERR_TKT_NYV error is returned."
         */
        KerberosTime startTime = (ticket.getEncPart().getStartTime() != null) ? ticket.getEncPart()
                .getStartTime() : ticket.getEncPart().getAuthTime();

        KerberosTime now = new KerberosTime();
        boolean isValidStartTime = startTime.lessThan(now);

        if (!isValidStartTime || (ticket.getEncPart().getFlags().isInvalid() && !isValidate))
        {
            // it hasn't yet become valid
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_NYV);
        }

        // TODO - doesn't take into account skew
        if (!ticket.getEncPart().getEndTime().greaterThan(now))
        {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_TKT_EXPIRED);
        }

        authHeader.getApOptions().setFlag(0/*ApOptions.MUTUAL_REQUIRED*/);

        return authenticator;
    }
}
