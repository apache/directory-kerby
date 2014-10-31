package org.haox.kerb.client.request;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.spec.KrbException;

import java.security.cert.Certificate;

public class CertAsRequest extends AsRequest {

    private Certificate cert;

    public CertAsRequest(KrbContext context) {
        super(context);
    }

    public void setCertificate(Certificate cert) {
        this.cert = cert;
    }

    @Override
    public void process() throws KrbException {
        throw new RuntimeException("To be implemented");
    }
}
