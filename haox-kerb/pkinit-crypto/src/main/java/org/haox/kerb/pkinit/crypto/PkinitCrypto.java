package org.haox.kerb.pkinit.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class PkinitCrypto {

    public static List<Certificate> getCerts(String certFile) throws IOException, CertificateException {
        InputStream is = new FileInputStream(new File(certFile));
        return getCerts(is);
    }

    public static List<Certificate> getCerts(InputStream is) throws IOException, CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certs =
                (Collection<? extends Certificate>) certFactory.generateCertificates(is);

        return new ArrayList<Certificate>(certs);
    }
}
