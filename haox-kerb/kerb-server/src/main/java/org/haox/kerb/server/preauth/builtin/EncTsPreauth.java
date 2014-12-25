package org.haox.kerb.server.preauth.builtin;

import org.haox.kerb.KrbErrorCode;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.preauth.builtin.EncTsPreauthMeta;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.preauth.AbstractPreauthPlugin;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.common.EncryptedData;
import org.haox.kerb.spec.common.EncryptionKey;
import org.haox.kerb.spec.common.KeyUsage;
import org.haox.kerb.spec.pa.PaDataEntry;
import org.haox.kerb.spec.pa.PaEncTsEnc;

public class EncTsPreauth extends AbstractPreauthPlugin {

    public EncTsPreauth() {
        super(new EncTsPreauthMeta());
    }

    @Override
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException {
        EncryptedData encData = KrbCodec.decode(paData.getPaDataValue(), EncryptedData.class);
        EncryptionKey clientKey = kdcRequest.getClientKey(encData.getEType());
        PaEncTsEnc timestamp = EncryptionUtil.unseal(encData, clientKey,
                KeyUsage.AS_REQ_PA_ENC_TS, PaEncTsEnc.class);

        KdcContext kdcContext = kdcRequest.getKdcContext();
        long clockSkew = kdcContext.getConfig().getAllowableClockSkew() * 1000;
        if (!timestamp.getAllTime().isInClockSkew(clockSkew)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED);
        }

        return true;
    }

}
