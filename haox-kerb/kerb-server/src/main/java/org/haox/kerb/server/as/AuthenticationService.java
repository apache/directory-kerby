package org.haox.kerb.server.as;

import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.shared.kerberos.KerberosConstants;
import org.apache.directory.shared.kerberos.exceptions.InvalidTicketException;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.server.KdcConfig;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.KerberosUtils;
import org.haox.kerb.server.PaUtil;
import org.haox.kerb.server.sam.SamException;
import org.haox.kerb.server.sam.SamSubsystem;
import org.haox.kerb.server.store.PrincipalStore;
import org.haox.kerb.server.store.PrincipalStoreEntry;
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

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import java.net.InetAddress;
import java.util.Date;
import java.util.List;

public class AuthenticationService
{
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationService.class);
    private static final Logger LOG_KRB = LoggerFactory.getLogger(Loggers.KERBEROS_LOG.getName());

    private static final String SERVICE_NAME = "Authentication Service (AS)";

    public void execute(AuthenticationContext authContext) throws Exception {

        int kerberosVersion = authContext.getRequest().getPvno();

        if (kerberosVersion != KerberosConstants.KERBEROS_V5) {
            LOG_KRB.error("Kerberos V{} is not supported", kerberosVersion);
            throw new KrbException(KrbErrorCode.KDC_ERR_BAD_PVNO);
        }

        selectEncryptionType(authContext);
        getClientEntry(authContext);
        verifyPolicy(authContext);
        verifySam(authContext);
        verifyEncryptedTimestamp(authContext);

        getServerEntry(authContext);
        generateTicket(authContext);
        buildReply(authContext);
    }

    private void selectEncryptionType(AuthenticationContext authContext) throws KrbException,
            InvalidTicketException, KrbException {

        LOG_KRB.debug("--> Selecting the EncryptionType");
        KdcContext kdcContext = authContext;
        KdcConfig config = kdcContext.getConfig();

        List<EncryptionType> requestedTypes = kdcContext.getRequest().getReqBody().getEtypes();
        LOG.debug("Encryption types requested by client {}.", requestedTypes);
        LOG_KRB.debug("Encryption types requested by client {}.", requestedTypes);

        EncryptionType bestType = EncryptionHandler.getBestEncryptionType(requestedTypes, kdcContext.getDefaultEtypes());

        LOG.debug("Session will use encryption type {}.", bestType);
        LOG_KRB.debug("Session will use encryption type {}.", bestType);

        if (bestType == null) {
            LOG_KRB.error("No encryptionType selected !");
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        kdcContext.setEncryptionType(bestType);
    }


    private void getClientEntry(AuthenticationContext authContext) throws KrbException,
            InvalidTicketException, KrbException {
        LOG_KRB.debug("--> Getting the client Entry");
        KdcReqBody kdcReqBody = authContext.getRequest().getReqBody();
        KerberosPrincipal principal = KerberosUtils.getKerberosPrincipal(
                kdcReqBody.getCname(),
                kdcReqBody.getRealm());
        PrincipalStore store = authContext.getStore();

        PrincipalStoreEntry storeEntry = KerberosUtils.getEntry(principal, store,
                KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        authContext.setClientEntry(storeEntry);

        LOG_KRB.debug("Found entry {} for principal {}", storeEntry.getDistinguishedName(), principal);
    }


    private static void verifyPolicy(AuthenticationContext authContext) throws KrbException,
            InvalidTicketException
    {
        LOG_KRB.debug("--> Verifying the policy");
        PrincipalStoreEntry entry = authContext.getClientEntry();

        if (entry.isDisabled())
        {
            LOG_KRB.error("The entry {} is disabled", entry.getDistinguishedName());
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }

        if (entry.isLockedOut())
        {
            LOG_KRB.error("The entry {} is locked out", entry.getDistinguishedName());
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }

        if (entry.getExpiration().lessThan(new Date().getTime()))
        {
            LOG_KRB.error("The entry {} has been revoked", entry.getDistinguishedName());
            throw new KrbException(KrbErrorCode.KDC_ERR_CLIENT_REVOKED);
        }
    }


    private void verifySam(AuthenticationContext authContext) throws KrbException, InvalidTicketException, KrbException {
        LOG.debug("Verifying using SAM subsystem.");
        LOG_KRB.debug("--> Verifying using SAM subsystem.");
        KdcReq request = authContext.getRequest();
        KdcConfig config = authContext.getConfig();

        PrincipalStoreEntry clientEntry = authContext.getClientEntry();
        String clientName = clientEntry.getPrincipal().getName();

        EncryptionKey clientKey = null;

        if (clientEntry.getSamType() != null) {
            if (LOG.isDebugEnabled() || LOG_KRB.isDebugEnabled()) {
                LOG.debug(
                        "Entry for client principal {} has a valid SAM type.  Invoking SAM subsystem for pre-authentication.",
                        clientName);
                LOG_KRB
                        .debug(
                                "Entry for client principal {} has a valid SAM type.  Invoking SAM subsystem for pre-authentication.",
                                clientName);
            }

            PaData preAuthData = request.getPaData();

            if ((preAuthData == null) || (preAuthData.getElements().size() == 0)) {
                LOG_KRB.debug("No PreAuth Data");
                KrbError krbError = preparePreAuthenticationError(authContext);
                throw new KrbErrorException(krbError);
            }

            try {
                for (PaDataEntry paData : preAuthData.getElements())
                {
                    if (paData.getPaDataType().equals(PaDataType.ENC_TIMESTAMP))
                    {
                        KerberosKey samKey = SamSubsystem.getInstance().verify(clientEntry,
                                paData.getPaDataValue());
                        clientKey = new EncryptionKey(samKey.getKeyType(), samKey.getEncoded());
                    }
                }
            } catch (SamException se) {
                LOG_KRB.error("Error : {}", se.getMessage());
                throw new KrbException(KrbErrorCode.KRB_ERR_GENERIC, se);
            }

            authContext.setClientKey(clientKey);
            authContext.setPreAuthenticated(true);

            if (LOG.isDebugEnabled() || LOG_KRB.isDebugEnabled()) {
                LOG.debug("Pre-authentication using SAM subsystem successful for {}.", clientName);
                LOG_KRB.debug("Pre-authentication using SAM subsystem successful for {}.", clientName);
            }
        }
    }


    private void verifyEncryptedTimestamp(AuthenticationContext authContext) throws KrbException,
            InvalidTicketException, KrbException {
        LOG.debug("Verifying using encrypted timestamp.");
        LOG_KRB.debug("--> Verifying using encrypted timestamp.");

        KdcConfig config = authContext.getConfig();
        KdcReq request = authContext.getRequest();
        PrincipalStoreEntry clientEntry = authContext.getClientEntry();
        String clientName = clientEntry.getPrincipal().getName();

        EncryptionKey clientKey = null;

        if (clientEntry.getSamType() == null) {
            LOG.debug(
                    "Entry for client principal {} has no SAM type.  Proceeding with standard pre-authentication.",
                    clientName);
            LOG_KRB.debug(
                    "Entry for client principal {} has no SAM type.  Proceeding with standard pre-authentication.",
                    clientName);

            EncryptionType encryptionType = authContext.getEncryptionType();
            clientKey = clientEntry.getKeyMap().get(encryptionType);

            if (clientKey == null)
            {
                LOG_KRB.error("No key for client {}", clientEntry.getDistinguishedName());
                throw new KrbException(KrbErrorCode.KDC_ERR_NULL_KEY);
            }

            if (config.isPaEncTimestampRequired()) {
                PaData preAuthData = request.getPaData();

                if (preAuthData == null) {
                    LOG_KRB.debug("PRE_AUTH required...");
                    throw new KrbErrorException(preparePreAuthenticationError(authContext));
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
                    LOG_KRB.error("No timestamp found");
                    throw new KrbErrorException(preparePreAuthenticationError(authContext));
                }

                if (!timestamp.getPaTimestamp().isInClockSkew(config.getAllowableClockSkew()))
                {
                    LOG_KRB.error("Timestamp not in delay");

                    throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED);
                }

                /*
                 * if(decrypted_enc_timestamp and usec is replay)
                 *         error_out(KDC_ERR_PREAUTH_FAILED);
                 * endif
                 * 
                 * add decrypted_enc_timestamp and usec to replay ccache;
                 */
            }
        }

        authContext.setClientKey(clientKey);
        authContext.setPreAuthenticated(true);

        if (LOG.isDebugEnabled() || LOG_KRB.isDebugEnabled())
        {
            LOG.debug("Pre-authentication by encrypted timestamp successful for {}.", clientName);
            LOG_KRB.debug("Pre-authentication by encrypted timestamp successful for {}.", clientName);
        }
    }


    private static void getServerEntry(AuthenticationContext authContext) throws KrbException,
            InvalidTicketException, KrbException {
        PrincipalName principal = authContext.getRequest().getReqBody().getSname();
        PrincipalStore store = authContext.getStore();

        LOG_KRB.debug("--> Getting the server entry for {}" + principal);

        KerberosPrincipal principalWithRealm = new KerberosPrincipal(principal.getName() + "@"
                + authContext.getRequest().getReqBody().getRealm());
        authContext.setServerEntry(KerberosUtils.getEntry(principalWithRealm, store,
                KrbErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN));
    }


    private static void generateTicket(AuthenticationContext authContext) throws KrbException,
            InvalidTicketException, KrbException {
        KdcReq request = authContext.getRequest();
        PrincipalName serverPrincipal = request.getReqBody().getSname();

        LOG_KRB.debug("--> Generating ticket for {}", serverPrincipal);

        EncryptionType encryptionType = authContext.getEncryptionType();
        EncryptionKey serverKey = authContext.getServerEntry().getKeyMap().get(encryptionType);

        PrincipalName ticketPrincipal = request.getReqBody().getSname();

        EncTicketPart encTicketPart = new EncTicketPart();
        KdcConfig config = authContext.getConfig();

        // The INITIAL flag indicates that a ticket was issued using the AS protocol.
        TicketFlags ticketFlags = new TicketFlags();
        encTicketPart.setFlags(ticketFlags);
        ticketFlags.setFlag(TicketFlag.INITIAL);

        // The PRE-AUTHENT flag indicates that the client used pre-authentication.
        if (authContext.isPreAuthenticated())
        {
            ticketFlags.setFlag(TicketFlag.PRE_AUTH);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.FORWARDABLE))
        {
            if (!config.isForwardableAllowed())
            {
                LOG_KRB.error("Ticket cannot be generated, because Forwadable is not allowed");
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.FORWARDABLE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.PROXIABLE))
        {
            if (!config.isProxiableAllowed())
            {
                LOG_KRB.error("Ticket cannot be generated, because proxyiable is not allowed");
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.PROXIABLE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.ALLOW_POSTDATE))
        {
            if (!config.isPostdatedAllowed())
            {
                LOG_KRB.error("Ticket cannot be generated, because Posdate is not allowed");
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.MAY_POSTDATE);
        }

        KdcOptions kdcOptions = request.getReqBody().getKdcOptions();

        if (kdcOptions.isFlagSet(KdcOption.RENEW)
                || kdcOptions.isFlagSet(KdcOption.VALIDATE)
                || kdcOptions.isFlagSet(KdcOption.PROXY)
                || kdcOptions.isFlagSet(KdcOption.FORWARDED)
                || kdcOptions.isFlagSet(KdcOption.ENC_TKT_IN_SKEY))
        {
            if (LOG_KRB.isDebugEnabled())
            {
                if (kdcOptions.isFlagSet(KdcOption.RENEW))
                {
                    LOG_KRB.error("Ticket cannot be generated, as it's a renew");

                }

                if (kdcOptions.isFlagSet(KdcOption.VALIDATE))
                {
                    LOG_KRB.error("Ticket cannot be generated, as it's a handle");

                }

                if (kdcOptions.isFlagSet(KdcOption.PROXY))
                {
                    LOG_KRB.error("Ticket cannot be generated, as it's a proxy");

                }

                if (kdcOptions.isFlagSet(KdcOption.FORWARDED))
                {
                    LOG_KRB.error("Ticket cannot be generated, as it's forwarded");

                }

                if (kdcOptions.isFlagSet(KdcOption.ENC_TKT_IN_SKEY))
                {
                    LOG_KRB.error("Ticket cannot be generated, as it's a user-to-user ");
                }
            }

            throw new KrbException(KrbErrorCode.KDC_ERR_BADOPTION);
        }

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

        /*
         * "If the requested starttime is absent, indicates a time in the past,
         * or is within the window of acceptable clock skew for the KDC and the
         * POSTDATE option has not been specified, then the starttime of the
         * ticket is set to the authentication server's current time."
         */
        if (startTime == null || startTime.lessThan(now) || startTime.isInClockSkew(config.getAllowableClockSkew())
                && !request.getReqBody().getKdcOptions().isFlagSet(KdcOption.POSTDATED))
        {
            startTime = now;
        }

        /*
         * "If it indicates a time in the future beyond the acceptable clock skew,
         * but the POSTDATED option has not been specified, then the error
         * KDC_ERR_CANNOT_POSTDATE is returned."
         */
        if ((startTime != null) && startTime.greaterThan(now)
                && !startTime.isInClockSkew(config.getAllowableClockSkew())
                && !request.getReqBody().getKdcOptions().isFlagSet(KdcOption.POSTDATED))
        {
            LOG_KRB.error("Ticket cannot be generated, as it's in the future and the Postdated option is not set");

            throw new KrbException(KrbErrorCode.KDC_ERR_CANNOT_POSTDATE);
        }

        /*
         * "Otherwise the requested starttime is checked against the policy of the
         * local realm and if the ticket's starttime is acceptable, it is set as
         * requested, and the INVALID flag is set in the new ticket."
         */
        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.POSTDATED))
        {
            if (!config.isPostdatedAllowed())
            {
                LOG_KRB.error("Ticket cannot be generated, as Podated is not allowed");
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

        /*
         * The end time is the minimum of (a) the requested till time or (b)
         * the start time plus maximum lifetime as configured in policy.
         */
        long endTime = Math.min(till, startTime.getTimeInSeconds() + config.getMaximumTicketLifetime());
        KerberosTime kerberosEndTime = new KerberosTime(endTime);
        encTicketPart.setEndTime(kerberosEndTime);

        /*
         * "If the requested expiration time minus the starttime (as determined
         * above) is less than a site-determined minimum lifetime, an error
         * message with code KDC_ERR_NEVER_VALID is returned."
         */
        if (kerberosEndTime.lessThan(startTime))
        {
            LOG_KRB.error("Ticket cannot be generated, as the endTime is below the startTime");
            throw new KrbException(KrbErrorCode.KDC_ERR_NEVER_VALID);
        }

        long ticketLifeTime = Math.abs(startTime.getTimeInSeconds() - kerberosEndTime.getTimeInSeconds());

        if (ticketLifeTime < config.getMinimumTicketLifetime()) {
            LOG_KRB.error("Ticket cannot be generated, as the Lifetime is too small");
            throw new KrbException(KrbErrorCode.KDC_ERR_NEVER_VALID);
        }

        /*
         * "If the requested expiration time for the ticket exceeds what was determined
         * as above, and if the 'RENEWABLE-OK' option was requested, then the 'RENEWABLE'
         * flag is set in the new ticket, and the renew-till value is set as if the
         * 'RENEWABLE' option were requested."
         */
        KerberosTime tempRtime = request.getReqBody().getRtime();

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.RENEWABLE_OK)
                && request.getReqBody().getTill().greaterThan(kerberosEndTime))
        {
            if (!config.isRenewableAllowed())
            {
                LOG_KRB.error("Ticket cannot be generated, as the renew date is exceeded");
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            request.getReqBody().getKdcOptions().setFlag(KdcOption.RENEWABLE);
            tempRtime = request.getReqBody().getTill();
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.RENEWABLE))
        {
            if (!config.isRenewableAllowed())
            {
                LOG_KRB.error("Ticket cannot be generated, as Renewable is not allowed");
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.RENEWABLE);

            if (tempRtime == null || tempRtime.getTimeInSeconds() == 0)
            {
                tempRtime = KerberosTime.NEVER;
            }

            /*
             * The renew-till time is the minimum of (a) the requested renew-till
             * time or (b) the start time plus maximum renewable lifetime as
             * configured in policy.
             */
            long renewTill = Math.min(tempRtime.getTimeInSeconds(),
                    startTime.getTimeInSeconds() + config.getMaximumRenewableLifetime());
            encTicketPart.setRenewtill(new KerberosTime(renewTill));
        }

        if (request.getReqBody().getAddresses() != null
                && request.getReqBody().getAddresses().getElements() != null
                && request.getReqBody().getAddresses().getElements().size() > 0)
        {
            encTicketPart.setClientAddresses(request.getReqBody().getAddresses());
        }
        else
        {
            if (!config.isEmptyAddressesAllowed())
            {
                LOG_KRB.error("Ticket cannot be generated, as the addresses are null, and it's not allowed");
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

        LOG.debug("Ticket will be issued for access to {}.", serverPrincipal.toString());
        LOG_KRB.debug("Ticket will be issued for access to {}.", serverPrincipal.toString());

        authContext.setTicket(newTicket);
    }


    private static void buildReply(AuthenticationContext authContext) throws KrbException,
            InvalidTicketException, KrbException {
        LOG_KRB.debug("--> Building reply");
        KdcReq request = authContext.getRequest();
        Ticket ticket = authContext.getTicket();

        AsRep reply = new AsRep();

        reply.setCname(request.getReqBody().getCname());
        reply.setCrealm(request.getReqBody().getRealm());
        reply.setTicket(ticket);

        EncKdcRepPart encKdcRepPart = new EncAsRepPart();
        //session key
        encKdcRepPart.setKey(ticket.getEncPart().getKey());

        // TODO - fetch lastReq for this client; requires identity
        // FIXME temporary fix, IMO we should create some new ATs to identity this info in DIT
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

        if (LOG.isDebugEnabled() || LOG_KRB.isDebugEnabled())
        {
            monitorContext(authContext);
            monitorReply(reply, encKdcRepPart);
        }

        EncryptionKey clientKey = authContext.getClientKey();
        EncryptedData encryptedData = EncryptionHandler.seal(encAsRepPart, clientKey,
                KeyUsage.AS_REP_ENCPART);
        reply.setEncryptedEncPart(encryptedData);
        //FIXME the below setter is useless, remove it
        reply.setEncPart(encKdcRepPart);

        authContext.setReply(reply);
    }

    private static void monitorContext(AuthenticationContext authContext)
    {
        try
        {
            long clockSkew = authContext.getConfig().getAllowableClockSkew();
            InetAddress clientAddress = authContext.getClientAddress();

            StringBuilder sb = new StringBuilder();

            sb.append("Monitoring " + SERVICE_NAME + " context:");

            sb.append("\n\t" + "clockSkew              " + clockSkew);
            sb.append("\n\t" + "clientAddress          " + clientAddress);

            KerberosPrincipal clientPrincipal = authContext.getClientEntry().getPrincipal();
            PrincipalStoreEntry clientEntry = authContext.getClientEntry();

            sb.append("\n\t" + "principal              " + clientPrincipal);
            sb.append("\n\t" + "cn                     " + clientEntry.getCommonName());
            sb.append("\n\t" + "realm                  " + clientEntry.getRealmName());
            sb.append("\n\t" + "principal              " + clientEntry.getPrincipal());
            sb.append("\n\t" + "SAM type               " + clientEntry.getSamType());

            PrincipalName serverPrincipal = authContext.getRequest().getReqBody().getSname();
            PrincipalStoreEntry serverEntry = authContext.getServerEntry();

            sb.append("\n\t" + "principal              " + serverPrincipal);
            sb.append("\n\t" + "cn                     " + serverEntry.getCommonName());
            sb.append("\n\t" + "realm                  " + serverEntry.getRealmName());
            sb.append("\n\t" + "principal              " + serverEntry.getPrincipal());
            sb.append("\n\t" + "SAM type               " + serverEntry.getSamType());

            EncryptionType encryptionType = authContext.getEncryptionType();
            int clientKeyVersion = 0;//clientEntry.getKeyMap().get(encryptionType).getKeyVersion();
            int serverKeyVersion = 0;//serverEntry.getKeyMap().get(encryptionType).getKeyVersion();
            sb.append("\n\t" + "Request key type       " + encryptionType);
            sb.append("\n\t" + "Client key version     " + clientKeyVersion);
            sb.append("\n\t" + "Server key version     " + serverKeyVersion);

            String message = sb.toString();

            LOG.debug(message);
            LOG_KRB.debug(message);
        }
        catch (Exception e)
        {
            // This is a monitor.  No exceptions should bubble up.
            LOG.error(I18n.err(I18n.ERR_154), e);
            LOG_KRB.error(I18n.err(I18n.ERR_154), e);
        }
    }


    private static void monitorReply(AsRep reply, EncKdcRepPart part)
    {
        if (LOG.isDebugEnabled())
        {
            try
            {
                StringBuffer sb = new StringBuffer();

                sb.append("Responding with " + SERVICE_NAME + " reply:");
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

                LOG.debug(message);
                LOG_KRB.debug(message);
            }
            catch (Exception e)
            {
                // This is a monitor.  No exceptions should bubble up.
                LOG.error(I18n.err(I18n.ERR_155), e);
                LOG_KRB.error(I18n.err(I18n.ERR_155), e);
            }
        }
    }

    private KrbError preparePreAuthenticationError(AuthenticationContext authContext) throws KrbException {
        EncryptionType requestedType = authContext.getEncryptionType();
        List<EncryptionType> encryptionTypes = authContext.getDefaultEtypes();
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
}
