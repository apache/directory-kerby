/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.server.request;

import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.HostAddresses;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.base.TransitedEncoding;
import org.apache.kerby.kerberos.kerb.type.base.TransitedEncodingType;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOption;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOptions;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlag;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlags;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handling ticket constructing, filling, and issuing.
 */
public abstract class TicketIssuer {
    private static final Logger LOG = LoggerFactory.getLogger(TicketIssuer.class);
    private final KdcRequest kdcRequest;

    public TicketIssuer(KdcRequest kdcRequest) {
        this.kdcRequest = kdcRequest;
    }

    protected KdcRequest getKdcRequest() {
        return kdcRequest;
    }

    public Ticket issueTicket() throws KrbException {
        KdcReq request = kdcRequest.getKdcReq();

        Ticket issuedTicket = new Ticket();

        PrincipalName serverPrincipal = getServerPrincipal();
        issuedTicket.setSname(serverPrincipal);

        String serverRealm = request.getReqBody().getRealm();
        issuedTicket.setRealm(serverRealm);

        EncTicketPart encTicketPart = makeEncTicketPart();

        EncryptionKey encryptionKey = getTicketEncryptionKey();

        EncryptedData encryptedData = EncryptionUtil.seal(encTicketPart,
            encryptionKey, KeyUsage.KDC_REP_TICKET);
        issuedTicket.setEncryptedEncPart(encryptedData);
        issuedTicket.setEncPart(encTicketPart);

        return issuedTicket;
    }

    public EncTicketPart makeEncTicketPart() throws KrbException {
        KdcReq request = kdcRequest.getKdcReq();

        EncTicketPart encTicketPart = new EncTicketPart();
        KdcConfig config = kdcRequest.getKdcContext().getConfig();

        TicketFlags ticketFlags = new TicketFlags();
        encTicketPart.setFlags(ticketFlags);
        ticketFlags.setFlag(TicketFlag.INITIAL);

        if (kdcRequest.isPreAuthenticated()) {
            ticketFlags.setFlag(TicketFlag.PRE_AUTH);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.FORWARDABLE)) {
            if (!config.isForwardableAllowed()) {
                LOG.warn("Forward is not allowed.");
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.FORWARDABLE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.PROXIABLE)) {
            if (!config.isProxiableAllowed()) {
                LOG.warn("Proxy is not allowed.");
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.PROXIABLE);
        }

        if (request.getReqBody().getKdcOptions().isFlagSet(KdcOption.ALLOW_POSTDATE)) {
            if (!config.isPostdatedAllowed()) {
                LOG.warn("Post date is not allowed.");
                throw new KrbException(KrbErrorCode.KDC_ERR_POLICY);
            }

            ticketFlags.setFlag(TicketFlag.MAY_POSTDATE);
        }

        EncryptionKey sessionKey = EncryptionHandler.random2Key(
                kdcRequest.getEncryptionType());
        encTicketPart.setKey(sessionKey);

        encTicketPart.setCname(getclientPrincipal());
        encTicketPart.setCrealm(request.getReqBody().getRealm());

        TransitedEncoding transEnc = getTransitedEncoding();
        encTicketPart.setTransited(transEnc);

        KdcOptions kdcOptions = request.getReqBody().getKdcOptions();

        KerberosTime now = KerberosTime.now();
        encTicketPart.setAuthTime(now);

        KerberosTime krbStartTime = request.getReqBody().getFrom();
        if (krbStartTime == null || krbStartTime.lessThan(now)
                || krbStartTime.isInClockSkew(config.getAllowableClockSkew())) {
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
        if (krbEndTime == null || krbEndTime.getTime() == 0) {
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

            if (krbRtime == null || krbRtime.getTime() == 0) {
                krbRtime = KerberosTime.NEVER;
            }
            KerberosTime allowedMaximumRenewableTime = krbStartTime;
            allowedMaximumRenewableTime = allowedMaximumRenewableTime
                    .extend(config.getMaximumRenewableLifetime() * 1000);
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

        AuthorizationData authData = makeAuthorizationData(kdcRequest,
                encTicketPart);
        if (authData != null) {
            encTicketPart.setAuthorizationData(authData);
        }

        return encTicketPart;
    }

    protected AuthorizationData makeAuthorizationData(KdcRequest kdcRequest,
            EncTicketPart encTicketPart) throws KrbException {
        return getKdcContext().getIdentityService()
                .getIdentityAuthorizationData(kdcRequest, encTicketPart);
    }

    protected KdcContext getKdcContext() {
        return kdcRequest.getKdcContext();
    }

    protected KdcReq getKdcReq() {
        return kdcRequest.getKdcReq();
    }

    protected PrincipalName getclientPrincipal() {
        if (kdcRequest.isToken()) {
            return new PrincipalName(kdcRequest.getToken().getSubject());
        } else {
            PrincipalName principalName = getKdcReq().getReqBody().getCname();
            if (getKdcRequest().isAnonymous()) {
                principalName.setNameType(NameType.NT_WELLKNOWN);
            }
            return principalName;
        }
    }

    protected PrincipalName getServerPrincipal() {
        return getKdcReq().getReqBody().getSname();
    }

    protected EncryptionType getTicketEncryptionType() throws KrbException {
        EncryptionType encryptionType = kdcRequest.getEncryptionType();
        return encryptionType;
    }

    protected EncryptionKey getTicketEncryptionKey() throws KrbException {
        EncryptionType encryptionType = getTicketEncryptionType();
        EncryptionKey serverKey =
                kdcRequest.getServerEntry().getKeys().get(encryptionType);
        return serverKey;
    }

    protected TransitedEncoding getTransitedEncoding() {
        TransitedEncoding transEnc = new TransitedEncoding();
        transEnc.setTrType(TransitedEncodingType.DOMAIN_X500_COMPRESS);
        byte[] empty = new byte[0];
        transEnc.setContents(empty);

        return transEnc;
    }
}
