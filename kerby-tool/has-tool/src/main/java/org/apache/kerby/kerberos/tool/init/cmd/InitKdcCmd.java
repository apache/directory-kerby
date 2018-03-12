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
package org.apache.kerby.kerberos.tool.init.cmd;

import org.apache.kerby.has.client.HasInitClient;
import org.apache.kerby.kerberos.kerb.KrbException;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Remote init kdc cmd
 */
public class InitKdcCmd extends InitCmd {

    public static final String USAGE = "Usage: init_kdc [-p] [path]\n"
        + "\tExample:\n"
        + "\t\tinit_kdc\n";

    public InitKdcCmd(HasInitClient client) {
        super(client);
    }

    @Override
    public void execute(String[] items) throws KrbException {
        if (items.length >= 2 && (items[1].startsWith("?") || items[1].startsWith("-help"))) {
                System.out.println(USAGE);
            return;
        }
        File path = getClient().getConfDir();
        if (items.length >= 3 && items[1].startsWith("-p")) {
            path = new File(items[2]);
            if (!path.exists() && !path.mkdirs()) {
                System.err.println("Cannot create file : " + items[2]);
                return;
            }
        }
        File adminKeytab = new File(path, "admin.keytab");

        HasInitClient client = getClient();
        InputStream content = client.initKdc();

        if (content == null) {
            return;
        }

        try (FileOutputStream fos = new FileOutputStream(adminKeytab)) {
            byte[] buffer = new byte[4 * 1024];
            int read;
            while ((read = content.read(buffer)) > 0) {
                fos.write(buffer, 0, read);
            }
            fos.close();
            content.close();
        } catch (FileNotFoundException e) {
            System.err.println("the admin keytab file not found. " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Errors occurred when getting the admin.keytab. " + e.getMessage());
        }

        System.out.println("admin.keytab has saved in : " + adminKeytab.getAbsolutePath()
            + ",\nplease safely save it to use kadmin.");

    }
}
