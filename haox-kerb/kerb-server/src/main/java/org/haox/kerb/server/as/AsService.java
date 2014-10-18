package org.haox.kerb.server.as;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.crypto.EncryptionHandler;
import org.haox.kerb.server.KdcConfig;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.KdcService;
import org.haox.kerb.identity.KrbIdentity;
import org.haox.kerb.spec.KrbErrorException;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.*;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;

public class AsService extends KdcService {
    private static final Logger LOG = LoggerFactory.getLogger(AsService.class);

    private static final String SERVICE_NAME = "Authentication Service (AS)";

    private void selectEncryptionType(AsContext authContext) throws KrbException {
        KdcContext kdcContext = authContext;
        KdcConfig config = kdcContext.getConfig();

        List<EncryptionType> requestedTypes = kdcContext.getRequest().getReqBody().getEtypes();
        LOG.debug("Encryption types requested by client {}.", requestedTypes);

        EncryptionType bestType = EncryptionUtil.getBestEncryptionType(requestedTypes,
                kdcContext.getConfig().getEncryptionTypes());

        LOG.debug("Session will use encryption type {}.", bestType);

        if (bestType == null) {
            throw new KrbException(KrbErrorCode.KDC_ERR_ETYPE_NOSUPP);
        }

        kdcContext.setEncryptionType(bestType);
    }

    private static void checkPolicy(AsContext authContext) throws KrbException {
        KrbIdentity entry = authContext.getClientEntry();

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

    private void verifyEncryptedTimestamp(AsContext authContext) throws KrbException {
        LOG.debug("Verifying using encrypted timestamp.");

        KdcConfig config = authContext.getConfig();
        KdcReq request = authContext.getRequest();
        KrbIdentity clientEntry = authContext.getClientEntry();
        String clientName = clientEntry.getPrincipal().getName();

        EncryptionKey clientKey = null;

        EncryptionType encryptionType = authContext.getEncryptionType();
        clientKey = clientEntry.getKeys().get(encryptionType);

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
    protected void authenticate(KdcContext requestContext) throws KrbException {
        AsContext asContext = (AsContext) requestContext;

        selectEncryptionType(asContext);
        checkPolicy(asContext);
    }
}
