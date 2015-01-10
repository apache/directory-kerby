package org.apache.commons.ssl;

import javax.net.SocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;

public class CRLSocket extends SSLClient {
    private final static CRLSocket secureInstance;
    private final static CRLSocket plainInstance;    

    static {
        CRLSocket sf1 = null, sf2 = null;
        try {
            sf1 = new CRLSocket();
            sf2 = new CRLSocket();
            sf2.setIsSecure(false);
        }
        catch (Exception e) {
            System.out.println("could not create CRLSocket: " + e);
            e.printStackTrace();
        }
        finally {
            secureInstance = sf1;
            plainInstance = sf2;            
        }
    }

    private CRLSocket() throws GeneralSecurityException, IOException {
        super();

        // For now we setup the usual trust infrastructure, but consumers
        // are encouraged to call getInstance().addTrustMaterial() or
        // getInstance().setTrustMaterial() to customize the trust.
        if (TrustMaterial.JSSE_CACERTS != null) {
            setTrustMaterial(TrustMaterial.JSSE_CACERTS);
        } else {
            setTrustMaterial(TrustMaterial.CACERTS);
        }
        setConnectTimeout(5000);
        setSoTimeout(5000);
        setCheckCRL(false);
    }

    public static SocketFactory getDefault() {
        return getSecureInstance();
    }

    public static CRLSocket getSecureInstance() {
        return secureInstance;
    }

    public static CRLSocket getPlainInstance() {
        return plainInstance;
    }

    public static void main(String[] args) throws Exception {
        String host = args[0];
        String port = args[1];
        String hello
                = "HEAD / HTTP/1.1\r\n"
                + "Host:" + host + ":" + port + "\r\n\r\n";
        byte[] helloBytes = hello.getBytes("UTF-8");

        System.out.println("About to getInstance() ");
        CRLSocket sf = getPlainInstance();
        long now = System.currentTimeMillis();
        System.out.println("About to create socket: [" + host + ":" + port + "]");
        Socket s = sf.createSocket(host, Integer.parseInt(port));
        long delay = System.currentTimeMillis() - now;
        System.out.println("Created socket! took " + delay + "ms ");
        OutputStream out = s.getOutputStream();
        out.write(helloBytes);
        out.flush();

        System.out.println("\n" + new String(helloBytes, "UTF-8"));

        InputStream in = s.getInputStream();
        int c = in.read();
        StringBuffer buf = new StringBuffer();
        System.out.println("Reading: ");
        System.out.println("================================================================================");
        while (c >= 0) {
            byte b = (byte) c;
            buf.append((char) b);
            System.out.print((char) b);
            if (-1 == buf.toString().indexOf("\r\n\r\n")) {
                c = in.read();
            } else {
                break;
            }
        }
        in.close();
        out.close();
        s.close();
    }

}
