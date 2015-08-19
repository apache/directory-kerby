/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/LDAPSocket.java $
 * $Revision: 165 $
 * $Date: 2014-04-24 16:48:09 -0700 (Thu, 24 Apr 2014) $
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

import javax.net.SocketFactory;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 28-Feb-2006
 */
public class LDAPSocket extends SSLClient {
    private static final LDAPSocket INSTANCE;

    static {
        LDAPSocket sf = null;
        try {
            sf = new LDAPSocket();
        } catch (Exception e) {
            System.out.println("could not create LDAPSocket: " + e);
            e.printStackTrace();
        } finally {
            INSTANCE = sf;
        }
    }

    private LDAPSocket() throws GeneralSecurityException, IOException {
        super();

        // For now we setup the usual trust infrastructure, but consumers
        // are encouraged to call getInstance().addTrustMaterial() or
        // getInstance().setTrustMaterial() to customize the trust.
        if (TrustMaterial.JSSE_CACERTS != null) {
            setTrustMaterial(TrustMaterial.JSSE_CACERTS);
        } else {
            setTrustMaterial(TrustMaterial.CACERTS);
        }
    }

    public static SocketFactory getDefault() {
        return getInstance();
    }

    public static LDAPSocket getInstance() {
        return INSTANCE;
    }

}
