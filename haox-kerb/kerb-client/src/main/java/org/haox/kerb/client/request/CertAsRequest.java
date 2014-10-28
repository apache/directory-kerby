package org.haox.kerb.client.request;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.spec.type.x509.Certificate;

public class CertAsRequest extends AsRequest {

    private Certificate cert;

    public CertAsRequest(KrbContext context) {
        super(context);
    }

    public void setCertificate(Certificate cert) {
        this.cert = cert;
    }
}
