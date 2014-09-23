package org.haox.kerb.server.as;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.server.*;
import org.haox.kerb.server.store.PrincipalStore;
import org.haox.kerb.server.store.PrincipalStoreEntry;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.KdcReqBody;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.util.Date;
import java.util.List;

public class AuthnService extends KdcService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthnService.class);

    private static final String SERVICE_NAME = "Authentication Service (AS)";

    private void selectEncryptionType(AuthnContext authContext) throws KrbException {
        KdcContext kdcContext = authContext;
        KdcConfig config = kdcContext.getConfig();

        List<EncryptionType> requestedTypes = kdcContext.getRequest().getReqBody().getEtypes();
        LOG.debug("Encryption types requested by client {}.", requestedTypes);

        EncryptionType bestType = EncryptionHandler.getBestEncryptionType(requestedTypes, kdcContext.getDefaultEtypes());

        LOG.debug("Session will use encryption type {}.", bestType);

        if (bestType == null) {
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        kdcContext.setEncryptionType(bestType);
    }

    private void getClientEntry(AuthnContext authContext) throws KrbException {
        KdcReqBody kdcReqBody = authContext.getRequest().getReqBody();
        KerberosPrincipal principal = KerberosUtils.getKerberosPrincipal(
                kdcReqBody.getCname(), kdcReqBody.getRealm());
        PrincipalStore store = authContext.getStore();

        PrincipalStoreEntry storeEntry = KerberosUtils.getEntry(principal, store,
                KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN);
        authContext.setClientEntry(storeEntry);
    }

    private static void checkPolicy(AuthnContext authContext) throws KrbException {
        PrincipalStoreEntry entry = authContext.getClientEntry();

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

    private void verifyEncryptedTimestamp(AuthnContext authContext) throws KrbException {
        LOG.debug("Verifying using encrypted timestamp.");

        KdcConfig config = authContext.getConfig();
        KdcReq request = authContext.getRequest();
        PrincipalStoreEntry clientEntry = authContext.getClientEntry();
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
        AuthnContext authnContext = (AuthnContext) requestContext;

        KdcConfig config = authnContext.getConfig();

        PrincipalStoreEntry clientEntry = authnContext.getClientEntry();
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
        AuthnContext authnContext = (AuthnContext) requestContext;

        selectEncryptionType(authnContext);
        getClientEntry(authnContext);
        checkPolicy(authnContext);
    }
}
