package org.haox.kerb.server.preauth.builtin;

import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.common.EncryptionUtil;
import org.haox.kerb.preauth.builtin.EncTsPreauthMeta;
import org.haox.kerb.server.preauth.AbstractPreauthPlugin;
import org.haox.kerb.server.preauth.PreauthContext;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptedData;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.KeyUsage;
import org.haox.kerb.spec.type.common.KrbErrorCode;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaEncTsEnc;

public class EncTsPreauth extends AbstractPreauthPlugin {

    public EncTsPreauth() {
        super(new EncTsPreauthMeta());
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

}
