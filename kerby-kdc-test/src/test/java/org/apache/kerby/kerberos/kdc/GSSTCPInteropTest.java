/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kdc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Before;

/**
 * This is an interop test using the Java GSS APIs against the Kerby KDC (using TCP)
 */
public class GSSTCPInteropTest extends GSSInteropTestBase {
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        
        String basedir = System.getProperty("basedir");
        if (basedir == null) {
            basedir = new File(".").getCanonicalPath();
        }
        
        // System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("java.security.auth.login.config", 
                           basedir + "/src/test/resources/kerberos.jaas");
        
        // Read in krb5.conf and substitute in the correct port
        File f = new File(basedir + "/src/test/resources/krb5.conf");

        FileInputStream inputStream = new FileInputStream(f);
        String content = IOUtils.toString(inputStream, "UTF-8");
        inputStream.close();
        content = content.replaceAll("port", "" + tcpPort);

        File f2 = new File(basedir + "/target/test-classes/krb5.conf");
        FileOutputStream outputStream = new FileOutputStream(f2);
        IOUtils.write(content, outputStream, "UTF-8");
        outputStream.close();

        System.setProperty("java.security.krb5.conf", f2.getPath());
    }

    @Override
    protected boolean allowUdp() {
        return false;
    }

}