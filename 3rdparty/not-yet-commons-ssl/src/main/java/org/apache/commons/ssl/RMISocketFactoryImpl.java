/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/RMISocketFactoryImpl.java $
 * $Revision: 166 $
 * $Date: 2014-04-28 11:40:25 -0700 (Mon, 28 Apr 2014) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLSocket;
import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.rmi.server.RMISocketFactory;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;


/**
 * An RMISocketFactory ideal for using RMI over SSL.  The server secures both
 * the registry and the remote objects.  The client assumes that either both
 * the registry and the remote objects will use SSL, or both will use
 * plain-socket.  The client is able to auto detect plain-socket registries
 * and downgrades itself to accomodate those.
 * <p/>
 * Unlike most existing RMI over SSL solutions in use (including Java 5's
 * javax.rmi.ssl.SslRMIClientSocketFactory), this one does proper SSL hostname
 * verification.  From the client perspective this is straighforward.  From
 * the server perspective we introduce a clever trick:  we perform an initial
 * "hostname verification" by trying the current value of
 * "java.rmi.server.hostname" against our server certificate.  If the
 * "java.rmi.server.hostname" System Property isn't set, we set it ourselves
 * using the CN value we extract from our server certificate!  (Some
 * complications arise should a wildcard certificate show up, but we try our
 * best to deal with those).
 * <p/>
 * An SSL server cannot be started without a private key.  We have defined some
 * default behaviour for trying to find a private key to use that we believe
 * is convenient and sensible:
 * <p/>
 * If running from inside Tomcat, we try to re-use Tomcat's private key and
 * certificate chain (assuming Tomcat-SSL on port 8443 is enabled).  If this
 * isn't available, we look for the "javax.net.ssl.keyStore" System property.
 * Finally, if that isn't available, we look for "~/.keystore" and assume
 * a password of "changeit".
 * <p/>
 * If after all these attempts we still failed to find a private key, the
 * RMISocketFactoryImpl() constructor will throw an SSLException.
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 22-Apr-2005
 */
public class RMISocketFactoryImpl extends RMISocketFactory {
    public final static String RMI_HOSTNAME_KEY = "java.rmi.server.hostname";
    private final static LogWrapper log = LogWrapper.getLogger(RMISocketFactoryImpl.class);

    private volatile SocketFactory defaultClient;
    private volatile ServerSocketFactory sslServer;
    private volatile String localBindAddress = null;
    private volatile int anonymousPort = 31099;
    private Map clientMap = new TreeMap();
    private Map serverSockets = new HashMap();
    private final SocketFactory plainClient = SocketFactory.getDefault();

    public RMISocketFactoryImpl() throws GeneralSecurityException, IOException {
        this(true);
    }

    /**
     * @param createDefaultServer If false, then we only set the default
     *                            client, and the default server is set to null.
     *                            If true, then a default server is also created.
     * @throws java.security.GeneralSecurityException bad things
     * @throws java.io.IOException              bad things
     */
    public RMISocketFactoryImpl(boolean createDefaultServer)
        throws GeneralSecurityException, IOException {
        SSLServer defaultServer = createDefaultServer ? new SSLServer() : null;
        SSLClient defaultClient = new SSLClient();

        // RMI calls to localhost will not check that host matches CN in
        // certificate.  Hopefully this is acceptable.  (The registry server
        // will followup the registry lookup with the proper DNS name to get
        // the remote object, anyway).
        HostnameVerifier verifier = HostnameVerifier.DEFAULT_AND_LOCALHOST;
        defaultClient.setHostnameVerifier(verifier);
        if (defaultServer != null) {
            defaultServer.setHostnameVerifier(verifier);
            // The RMI server will try to re-use Tomcat's "port 8443" SSL
            // Certificate if possible.
            defaultServer.useTomcatSSLMaterial();
            X509Certificate[] x509 = defaultServer.getAssociatedCertificateChain();
            if (x509 == null || x509.length < 1) {
                throw new SSLException("Cannot initialize RMI-SSL Server: no KeyMaterial!");
            }
            setServer(defaultServer);
        }
        setDefaultClient(defaultClient);
    }

    public void setServer(ServerSocketFactory f)
        throws GeneralSecurityException, IOException {
        this.sslServer = f;
        if (f instanceof SSLServer) {
            final HostnameVerifier VERIFIER;
            VERIFIER = HostnameVerifier.DEFAULT_AND_LOCALHOST;

            final SSLServer ssl = (SSLServer) f;
            final X509Certificate[] chain = ssl.getAssociatedCertificateChain();
            String[] cns = Certificates.getCNs(chain[0]);
            String[] subjectAlts = Certificates.getDNSSubjectAlts(chain[0]);
            LinkedList names = new LinkedList();
            if (cns != null && cns.length > 0) {
                // Only first CN is used.  Not going to get into the IE6 nonsense
                // where all CN values are used.
                names.add(cns[0]);
            }
            if (subjectAlts != null && subjectAlts.length > 0) {
                names.addAll(Arrays.asList(subjectAlts));
            }

            String rmiHostName = System.getProperty(RMI_HOSTNAME_KEY);
            // If "java.rmi.server.hostname" is already set, don't mess with it.
            // But blowup if it's not going to work with our SSL Server
            // Certificate!
            if (rmiHostName != null) {
                try {
                    VERIFIER.check(rmiHostName, cns, subjectAlts);
                }
                catch (SSLException ssle) {
                    String s = ssle.toString();
                    throw new SSLException(RMI_HOSTNAME_KEY + " of " + rmiHostName + " conflicts with SSL Server Certificate: " + s);
                }
            } else {
                // If SSL Cert only contains one non-wild name, just use that and
                // hope for the best.
                boolean hopingForBest = false;
                if (names.size() == 1) {
                    String name = (String) names.get(0);
                    if (!name.startsWith("*")) {
                        System.setProperty(RMI_HOSTNAME_KEY, name);
                        log.warn("commons-ssl '" + RMI_HOSTNAME_KEY + "' set to '" + name + "' as found in my SSL Server Certificate.");
                        hopingForBest = true;
                    }
                }
                if (!hopingForBest) {
                    // Help me, Obi-Wan Kenobi; you're my only hope.  All we can
                    // do now is grab our internet-facing addresses, reverse-lookup
                    // on them, and hope that one of them validates against our
                    // server cert.
                    Set s = getMyInternetFacingIPs();
                    Iterator it = s.iterator();
                    while (it.hasNext()) {
                        String name = (String) it.next();
                        try {
                            VERIFIER.check(name, cns, subjectAlts);
                            System.setProperty(RMI_HOSTNAME_KEY, name);
                            log.warn("commons-ssl '" + RMI_HOSTNAME_KEY + "' set to '" + name + "' as found by reverse-dns against my own IP.");
                            hopingForBest = true;
                            break;
                        }
                        catch (SSLException ssle) {
                            // next!
                        }
                    }
                }
                if (!hopingForBest) {
                    throw new SSLException("'" + RMI_HOSTNAME_KEY + "' not present.  Must work with my SSL Server Certificate's CN field: " + names);
                }
            }
        }
        trustOurself();
    }

    public void setLocalBindAddress(String localBindAddress) {
        this.localBindAddress = localBindAddress;
    }

    public void setAnonymousPort(int port) {
        this.anonymousPort = port;
    }

    public void setDefaultClient(SocketFactory f)
        throws GeneralSecurityException, IOException {
        this.defaultClient = f;
        trustOurself();
    }

    public void setClient(String host, SocketFactory f)
        throws GeneralSecurityException, IOException {
        if (f != null && sslServer != null) {
            boolean clientIsCommonsSSL = f instanceof SSLClient;
            boolean serverIsCommonsSSL = sslServer instanceof SSLServer;
            if (clientIsCommonsSSL && serverIsCommonsSSL) {
                SSLClient c = (SSLClient) f;
                SSLServer s = (SSLServer) sslServer;
                trustEachOther(c, s);
            }
        }
        Set names = hostnamePossibilities(host);
        Iterator it = names.iterator();
        synchronized (this) {
            while (it.hasNext()) {
                clientMap.put(it.next(), f);
            }
        }
    }

    public void removeClient(String host) {
        Set names = hostnamePossibilities(host);
        Iterator it = names.iterator();
        synchronized (this) {
            while (it.hasNext()) {
                clientMap.remove(it.next());
            }
        }
    }

    public synchronized void removeClient(SocketFactory sf) {
        Iterator it = clientMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            Object o = entry.getValue();
            if (sf.equals(o)) {
                it.remove();
            }
        }
    }

    private Set hostnamePossibilities(String host) {
        host = host != null ? host.toLowerCase().trim() : "";
        if ("".equals(host)) {
            return Collections.EMPTY_SET;
        }
        TreeSet names = new TreeSet();
        names.add(host);
        InetAddress[] addresses;
        try {
            // If they gave us "hostname.com", this will give us the various
            // IP addresses:
            addresses = InetAddress.getAllByName(host);
            for (int i = 0; i < addresses.length; i++) {
                String name1 = addresses[i].getHostName();
                String name2 = addresses[i].getHostAddress();
                names.add(name1.trim().toLowerCase());
                names.add(name2.trim().toLowerCase());
            }
        }
        catch (UnknownHostException uhe) {
            /* oh well, nothing found, nothing to add for this client */
        }

        try {
            host = InetAddress.getByName(host).getHostAddress();

            // If they gave us "1.2.3.4", this will hopefully give us
            // "hostname.com" so that we can then try and find any other
            // IP addresses associated with that name.
            host = InetAddress.getByName(host).getHostName();
            names.add(host.trim().toLowerCase());
            addresses = InetAddress.getAllByName(host);
            for (int i = 0; i < addresses.length; i++) {
                String name1 = addresses[i].getHostName();
                String name2 = addresses[i].getHostAddress();
                names.add(name1.trim().toLowerCase());
                names.add(name2.trim().toLowerCase());
            }
        }
        catch (UnknownHostException uhe) {
            /* oh well, nothing found, nothing to add for this client */
        }
        return names;
    }

    private void trustOurself()
        throws GeneralSecurityException, IOException {
        if (defaultClient == null || sslServer == null) {
            return;
        }
        boolean clientIsCommonsSSL = defaultClient instanceof SSLClient;
        boolean serverIsCommonsSSL = sslServer instanceof SSLServer;
        if (clientIsCommonsSSL && serverIsCommonsSSL) {
            SSLClient c = (SSLClient) defaultClient;
            SSLServer s = (SSLServer) sslServer;
            trustEachOther(c, s);
        }
    }

    private void trustEachOther(SSLClient client, SSLServer server)
        throws GeneralSecurityException, IOException {
        if (client != null && server != null) {
            // Our own client should trust our own server.
            X509Certificate[] certs = server.getAssociatedCertificateChain();
            if (certs != null && certs[0] != null) {
                TrustMaterial tm = new TrustMaterial(certs[0]);
                client.addTrustMaterial(tm);
            }

            // Our own server should trust our own client.
            certs = client.getAssociatedCertificateChain();
            if (certs != null && certs[0] != null) {
                TrustMaterial tm = new TrustMaterial(certs[0]);
                server.addTrustMaterial(tm);
            }
        }
    }

    public ServerSocketFactory getServer() { return sslServer; }

    public SocketFactory getDefaultClient() { return defaultClient; }

    public synchronized SocketFactory getClient(String host) {
        host = host != null ? host.trim().toLowerCase() : "";
        return (SocketFactory) clientMap.get(host);
    }

    public synchronized ServerSocket createServerSocket(int port)
        throws IOException {
        // Re-use existing ServerSocket if possible.
        if (port == 0) {
            port = anonymousPort;
        }
        Integer key = new Integer(port);
        ServerSocket ss = (ServerSocket) serverSockets.get(key);
        if (ss == null || ss.isClosed()) {
            if (ss != null && ss.isClosed()) {
                System.out.println("found closed server on port: " + port);
            }
            log.debug("commons-ssl RMI server-socket: listening on port " + port);
            ss = sslServer.createServerSocket(port);
            serverSockets.put(key, ss);
        }
        return ss;
    }

    public Socket createSocket(String host, int port)
        throws IOException {
        host = host != null ? host.trim().toLowerCase() : "";
        InetAddress local = null;
        String bindAddress = localBindAddress;
        if (bindAddress == null) {
            bindAddress = System.getProperty(RMI_HOSTNAME_KEY);
            if (bindAddress != null) {
                local = InetAddress.getByName(bindAddress);
                if (!local.isLoopbackAddress()) {
                    String ip = local.getHostAddress();
                    Set myInternetIps = getMyInternetFacingIPs();
                    if (!myInternetIps.contains(ip)) {
                        log.warn("Cannot bind to " + ip + " since it doesn't exist on this machine.");
                        // Not going to be able to bind as this.  Our RMI_HOSTNAME_KEY
                        // must be set to some kind of proxy in front of us.  So we
                        // still want to use it, but we can't bind to it.
                        local = null;
                        bindAddress = null;
                    }
                }
            }
        }
        if (bindAddress == null) {
            // Our last resort - let's make sure we at least use something that's
            // internet facing!
            bindAddress = getMyDefaultIP();
        }
        if (local == null && bindAddress != null) {
            local = InetAddress.getByName(bindAddress);
            localBindAddress = local.getHostName();
        }

        SocketFactory sf;
        synchronized (this) {
            sf = (SocketFactory) clientMap.get(host);
        }
        if (sf == null) {
            sf = defaultClient;
        }

        Socket s = null;
        SSLSocket ssl = null;
        int soTimeout = Integer.MIN_VALUE;
        IOException reasonForPlainSocket = null;
        boolean tryPlain = false;
        try {
            s = sf.createSocket(host, port, local, 0);
            soTimeout = s.getSoTimeout();
            if (!(s instanceof SSLSocket)) {
                // Someone called setClient() or setDefaultClient() and passed in
                // a plain socket factory.  Okay, nothing to see, move along.
                return s;
            } else {
                ssl = (SSLSocket) s;
            }

            // If we don't get the peer certs in 15 seconds, revert to plain
            // socket.
            ssl.setSoTimeout(15000);
            ssl.getSession().getPeerCertificates();

            // Everything worked out okay, so go back to original soTimeout.
            ssl.setSoTimeout(soTimeout);
            return ssl;
        }
        catch (IOException ioe) {
            // SSL didn't work.  Let's analyze the IOException to see if maybe
            // we're accidentally attempting to talk to a plain-socket RMI
            // server.
            Throwable t = ioe;
            while (!tryPlain && t != null) {
                tryPlain = tryPlain || t instanceof EOFException;
                tryPlain = tryPlain || t instanceof InterruptedIOException;
                tryPlain = tryPlain || t instanceof SSLProtocolException;
                t = t.getCause();
            }
            if (!tryPlain && ioe instanceof SSLPeerUnverifiedException) {
                try {
                    if (ssl != null) {
                        ssl.startHandshake();
                    }
                }
                catch (IOException ioe2) {
                    // Stacktrace from startHandshake() will be more descriptive
                    // then the one we got from getPeerCertificates().
                    ioe = ioe2;
                    t = ioe2;
                    while (!tryPlain && t != null) {
                        tryPlain = tryPlain || t instanceof EOFException;
                        tryPlain = tryPlain || t instanceof InterruptedIOException;
                        tryPlain = tryPlain || t instanceof SSLProtocolException;
                        t = t.getCause();
                    }
                }
            }
            if (!tryPlain) {
                log.debug("commons-ssl RMI-SSL failed: " + ioe);
                throw ioe;
            } else {
                reasonForPlainSocket = ioe;
            }
        }
        finally {
            // Some debug logging:
            boolean isPlain = tryPlain || (s != null && ssl == null);
            String socket = isPlain ? "RMI plain-socket " : "RMI ssl-socket ";
            String localIP = local != null ? local.getHostAddress() : "ANY";
            StringBuffer buf = new StringBuffer(64);
            buf.append(socket);
            buf.append(localIP);
            buf.append(" --> ");
            buf.append(host);
            buf.append(":");
            buf.append(port);
            log.debug(buf.toString());
        }

        // SSL didn't work.  Remote server either timed out, or sent EOF, or
        // there was some kind of SSLProtocolException.  (Any other problem
        // would have caused an IOException to be thrown, so execution wouldn't
        // have made it this far).  Maybe plain socket will work in these three
        // cases.
        sf = plainClient;
        s = JavaImpl.connect(null, sf, host, port, local, 0, 15000, null);
        if (soTimeout != Integer.MIN_VALUE) {
            s.setSoTimeout(soTimeout);
        }

        try {
            // Plain socket worked!  Let's remember that for next time an RMI call
            // against this host happens.
            setClient(host, plainClient);
            String msg = "RMI downgrading from SSL to plain-socket for " + host + " because of " + reasonForPlainSocket;
            log.warn(msg, reasonForPlainSocket);
        }
        catch (GeneralSecurityException gse) {
            throw new RuntimeException("can't happen because we're using plain socket", gse);
            // won't happen because we're using plain socket, not SSL.
        }

        return s;
    }


    public static String getMyDefaultIP() {
        String anInternetIP = "64.111.122.211";
        String ip = null;
        try {
            DatagramSocket dg = new DatagramSocket();
            dg.setSoTimeout(250);
            // 64.111.122.211 is juliusdavies.ca.
            // This code doesn't actually send any packets (so no firewalls can
            // get in the way).  It's just a neat trick for getting our
            // internet-facing interface card.
            InetAddress addr = Util.toInetAddress(anInternetIP);
            dg.connect(addr, 12345);
            InetAddress localAddr = dg.getLocalAddress();
            ip = localAddr.getHostAddress();
            // log.debug( "Using bogus UDP socket (" + anInternetIP + ":12345), I think my IP address is: " + ip );
            dg.close();
            if (localAddr.isLoopbackAddress() || "0.0.0.0".equals(ip)) {
                ip = null;
            }
        }
        catch (IOException ioe) {
            log.debug("Bogus UDP didn't work: " + ioe);
        }
        return ip;
    }

    public static SortedSet getMyInternetFacingIPs() throws SocketException {
        TreeSet set = new TreeSet();
        Enumeration en = NetworkInterface.getNetworkInterfaces();
        while (en.hasMoreElements()) {
            NetworkInterface ni = (NetworkInterface) en.nextElement();
            Enumeration en2 = ni.getInetAddresses();
            while (en2.hasMoreElements()) {
                InetAddress addr = (InetAddress) en2.nextElement();
                if (!addr.isLoopbackAddress()) {
                    String ip = addr.getHostAddress();
                    String reverse = addr.getHostName();
                    // IP:
                    set.add(ip);
                    // Reverse-Lookup:
                    set.add(reverse);

                }
            }
        }
        return set;
    }

}
