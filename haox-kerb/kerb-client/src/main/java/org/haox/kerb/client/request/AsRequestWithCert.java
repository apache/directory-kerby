package org.haox.kerb.client.request;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaDataType;

public class AsRequestWithCert extends AsRequest {

    public static final String ANONYMOUS_PRINCIPAL = "ANONYMOUS@WELLKNOWN:ANONYMOUS";

    public AsRequestWithCert(KrbContext context) {
        super(context);

        setAllowedPreauth(PaDataType.PK_AS_REQ);
    }

    @Override
    public void process() throws KrbException {
        throw new RuntimeException("To be implemented");
    }

    @Override
    public KrbOptions getPreauthOptions() {
        KrbOptions results = new KrbOptions();

        KrbOptions krbOptions = getKrbOptions();
        results.add(krbOptions.getOption(KrbOption.PKINIT_X509_CERTIFICATE));
        results.add(krbOptions.getOption(KrbOption.PKINIT_X509_ANCHORS));
        results.add(krbOptions.getOption(KrbOption.PKINIT_X509_PRIVATE_KEY));
        results.add(krbOptions.getOption(KrbOption.PKINIT_X509_IDENTITY));
        results.add(krbOptions.getOption(KrbOption.PKINIT_USING_RSA));

        return results;
    }

}
