package org.apache.kerberos.kerb.server.preauth.builtin;

import org.apache.kerberos.kerb.KrbErrorCode;
import org.apache.kerberos.kerb.codec.KrbCodec;
import org.apache.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.preauth.builtin.EncTsPreauthMeta;
import org.apache.kerberos.kerb.server.KdcContext;
import org.apache.kerberos.kerb.server.preauth.AbstractPreauthPlugin;
import org.apache.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.EncryptedData;
import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.common.KeyUsage;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerberos.kerb.spec.pa.PaEncTsEnc;

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
