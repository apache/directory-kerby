/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/rmi/Test.java $
 * $Revision: 121 $
 * $Date: 2007-11-13 21:26:57 -0800 (Tue, 13 Nov 2007) $
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

package org.apache.commons.ssl.rmi;

import org.apache.commons.ssl.LogWrapper;
import org.apache.commons.ssl.RMISocketFactoryImpl;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.RMISocketFactory;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 22-Feb-2007
 */
public class Test {
    private final static LogWrapper log = LogWrapper.getLogger(Test.class);
    private final static String TEST_DATE_NAME = "/org.apache.commons.ssl.rmi.testdate";
    private final static String TEST_INT_NAME = "/org.apache.commons.ssl.rmi.testint";
    protected final static int PORT;
    protected final static String URL;

    private static boolean rmiRunning = false;

    static {
        int port = 1099;
        String host = "127.0.0.1";
        PORT = port;
        // e.g. "rmi://localhost:1099/"
        URL = "rmi://" + host + ":" + port;
    }

    /**
     * <p/>
     * JNDI/RMI lookup wrapper.  Appends "java:" if we expect
     * binding/lookup to occur in the same JVM.  Otherwise, appends "rmi:".
     * </p>
     *
     * @param ref String reference.
     * @return Object  Object previously bound with String reference.
     * @throws java.rmi.RemoteException       rmi problem
     * @throws java.rmi.NotBoundException     rmi problem
     * @throws java.net.MalformedURLException rmi problem
     */
    public static Object lookup(String ref)
        throws RemoteException, NotBoundException, MalformedURLException {
        return Naming.lookup(URL + ref);
    }

    /**
     * <p/>
     * JNDI/RMI rebind wrapper for the UCS.  Appends "java:" if we expect
     * binding/lookup to occur in the same JVM.  Otherwise, append "rmi:".
     * </p><p>
     * Also attempts to start a naming server on the localhost if one is
     * not already running.  Currently we use RMI.
     * </p>
     *
     * @param ref String reference to bind with.
     * @param obj Object to bind.
     * @throws java.rmi.RemoteException       rmi problem
     * @throws java.net.MalformedURLException rmi problem
     */
    public static void rebind(String ref, Remote obj)
        throws RemoteException, MalformedURLException {
        requireNameServer();
        String realRef = URL + ref;
        Naming.rebind(realRef, obj);
        try {
            Object o = lookup(ref);
            log.debug("Bound " + o.getClass().getName() + " to [" + realRef + "]");
        }
        catch (NotBoundException nbe) {
            log.debug("Error binding " + obj.getClass().getName() + " to [" + realRef + "]");
        }
    }

    private static void rebindTest() throws Exception {
        Remote remoteTest = new DateRMI();
        Naming.rebind(URL + TEST_DATE_NAME, remoteTest);
        Object o = Naming.lookup(URL + TEST_DATE_NAME);
        if (!remoteTest.equals(o)) {
            throw new RuntimeException("rmi: Test failed. Lookup != Rebind");
        }
    }

    /**
     * <p/>
     * Attempts to start a naming server on the localhost if one is not
     * already running.
     * </p>
     */
    private synchronized static void requireNameServer() {
        if (rmiRunning) {
            // We've already established that the name server is running.
            return;
        }
        try {
            // If this rebind works, then the naming server is running.
            rebindTest();
            rmiRunning = true;
        }
        catch (Exception e) {
            Test.tryToStartNameServer();
            try {
                // Okay, we've started our naming server.  Now we must perform a
                // quick test to see that it's actually doing something.
                rebindTest();
                log.debug(Test.class.getName() + " successfully started.");
                rmiRunning = true;
                return;
            }
            catch (Exception e2) {
                e2.printStackTrace();
                log.error(e2.getMessage(), e2);
            }

            String msg = Test.class.getName() + " cannot start.";
            log.error(msg);
            throw new RuntimeException(msg);
        }
    }

    public static void tryToStartNameServer() {
        String className = Test.class.getName();
        log.debug(className + " probably not running.   Trying to start one.");
        try {
            LocateRegistry.createRegistry(PORT);
            log.debug("registry on " + PORT + " started!");
        }
        catch (Exception problem) {
            // bah - no luck
            problem.printStackTrace();
            log.warn(problem, problem);
        }
    }


    public static void main(String[] args) throws Exception {
        System.setProperty(RMISocketFactoryImpl.RMI_HOSTNAME_KEY, "localhost");
        RMISocketFactoryImpl impl = new RMISocketFactoryImpl();
        RMISocketFactory.setSocketFactory(impl);

        if (args.length > 0) {

        } else {
            Test.requireNameServer();
            Test.rebindTest();

            IntegerRMI remoteInt = new IntegerRMI();
            Test.rebind(TEST_INT_NAME, remoteInt);
        }

        Object o = Test.lookup(TEST_DATE_NAME);
        RemoteDate rd = (RemoteDate) o;
        System.out.println("The remote-date is: " + rd.getDate());

        o = Test.lookup(TEST_INT_NAME);
        RemoteInteger ri = (RemoteInteger) o;
        System.out.println("The remote-int  is: " + ri.getInt());

    }


}
