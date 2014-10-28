package org.haox.kerb.server.preauth;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.TimestampPreauthBase;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;

public class TimestampPreauth extends TimestampPreauthBase implements KdcPreauth {

    private KdcContext kdcContext;

    public void init(KdcContext kdcContext) {
        this.kdcContext = kdcContext;
    }

    @Override
    public void provideEData(PreauthContext preauthContext) throws KrbException {

    }

    @Override
    public void verify(PreauthContext preauthContext, PaDataEntry paData) throws KrbException {
        EncryptedData encData = KrbCodec.decode(paData.getPaDataValue(), EncryptedData.class);
        EncryptionKey clientKey = preauthContext.getClientKey(encData.getEType());
        PaEncTsEnc timestamp = EncryptionUtil.unseal(encData, clientKey,
                KeyUsage.AS_REQ_PA_ENC_TS, PaEncTsEnc.class);

        long clockSkew = kdcContext.getConfig().getAllowableClockSkew() * 1000;
        if (!timestamp.getAllTime().isInClockSkew(clockSkew)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED);
        }
    }

    @Override
    public void providePaData(PreauthContext preauthContext, PaData paData) {

    }

    @Override
    public PaFlags getFlags(PreauthContext preauthContext, PaDataType paType) {
        return null;
    }

    @Override
    public void destroy() {

    }
}
