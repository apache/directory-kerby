/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/SSLProxyServer.java $
 * $Revision: 132 $
 * $Date: 2008-01-11 21:20:26 -0800 (Fri, 11 Jan 2008) $
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

import org.apache.commons.ssl.util.ReadLine;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 5-May-2006
 */
public class SSLProxyServer {

    public static void main(String[] args) throws Exception {
        int port = 7444;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }

        ServerSocket ss = new ServerSocket(port);

        System.out.println("SSL Proxy server listening on port: " + port);
        while (true) {
            Socket s = ss.accept();
            s.setSoTimeout(10000);
            ProxyRunnable r = new ProxyRunnable(s);
            new Thread(r).start();
        }

    }

    public static class ProxyRunnable implements Runnable {
        private Socket s;

        public ProxyRunnable(Socket s) {
            this.s = s;
        }

        public void run() {
            InputStream in = null;
            OutputStream out = null;
            InputStream newIn = null;
            OutputStream newOut = null;
            Socket newSocket = new Socket();
            System.out.println("Socket accepted!");
            try {
                in = s.getInputStream();
                out = s.getOutputStream();
                ReadLine readLine = new ReadLine(in);
                String line = readLine.next();
                line = line.trim();
                String connect = line.substring(0, "CONNECT".length());
                InetSocketAddress addr = null;
                if ("CONNECT".equalsIgnoreCase(connect)) {
                    line = line.substring("CONNECT".length()).trim();
                    line = line.substring(0, line.length() - "HTTP/1.1".length()).trim();
                    HostPort hostPort = Util.toAddress(line, 443);
                    addr = new InetSocketAddress(hostPort.host, hostPort.port);
                    System.out.println("Attempting to proxy to: " + line);
                } else {
                    throw new IOException("not a proxy request: " + line);
                }

                int avail = in.available();
                in.skip(avail);
                Thread.yield();
                avail = in.available();
                while (avail != 0) {
                    in.skip(avail);
                    Thread.yield();
                    avail = in.available();
                }

                InetSocketAddress local = new InetSocketAddress(0);
                newSocket.setSoTimeout(10000);
                newSocket.bind(local);
                newSocket.connect(addr, 5000);
                newIn = newSocket.getInputStream();
                newOut = newSocket.getOutputStream();

                out.write("HTTP/1.1 200 OKAY\r\n\r\n".getBytes());
                out.flush();

                final IOException[] e = new IOException[1];
                final InputStream rIn = in;
                final OutputStream rNewOut = newOut;
                Runnable r = new Runnable() {
                    public void run() {
                        try {
                            byte[] buf = new byte[4096];
                            int read = rIn.read(buf);
                            while (read >= 0) {
                                if (read > 0) {
                                    rNewOut.write(buf, 0, read);
                                    rNewOut.flush();
                                }
                                read = rIn.read(buf);
                            }
                        }
                        catch (IOException ioe) {
                            e[0] = ioe;
                        }
                    }
                };
                new Thread(r).start();

                byte[] buf = new byte[4096];
                int read = newIn.read(buf);
                while (read >= 0) {
                    if (read > 0) {
                        out.write(buf, 0, read);
                        out.flush();
                    }
                    if (e[0] != null) {
                        throw e[0];
                    }
                    read = newIn.read(buf);
                }


            }
            catch (IOException ioe) {
                try {
                    if (out != null) {
                        out.close();
                    }
                    if (in != null) {
                        in.close();
                    }
                    s.close();
                }
                catch (Exception e) {
                }

                try {
                    if (newOut != null) {
                        newOut.close();
                    }
                    if (newIn != null) {
                        newIn.close();
                    }
                    newSocket.close();
                }
                catch (Exception e) {
                }


                if (ioe instanceof InterruptedIOException) {
                    System.out.println("Socket closed after 10 second timeout.");
                } else {
                    ioe.printStackTrace();
                }

            }
        }
    }

}
