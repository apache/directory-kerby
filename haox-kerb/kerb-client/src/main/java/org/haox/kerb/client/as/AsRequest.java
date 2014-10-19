package org.haox.kerb.client.as;

import org.haox.kerb.client.KdcRequest;
import org.haox.kerb.client.KrbContext;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KerberosTime;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.HostAddresses;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.haox.kerb.spec.type.kdc.KdcReq;
import org.haox.kerb.spec.type.kdc.KdcReqBody;

import java.util.List;

public class AsRequest extends KdcRequest {
    private AsReq asReq;

    public AsRequest(KrbContext context) {
        super(context);
        this.asReq = new AsReq();
    }

    @Override
    public KdcReq makeKdcRequest() throws KrbException {
        KdcReqBody body = makeReqBody();

        asReq.setReqBody(body);

        if (isPreauthRequired()) {
            PaDataEntry tsPaEntry = makeTimeStampPaDataEntry();
            asReq.addPaData(tsPaEntry);
        }

        return asReq;
    }
}
