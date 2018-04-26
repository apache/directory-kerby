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

/**
 * Remote set plugin cmd
 */
public class SetPluginCmd extends InitCmd {

    public static final String USAGE = "Usage: set_plugin <plugin>\n"
        + "\tExample:\n"
        + "\t\tset_plugin RAM\n";

    public SetPluginCmd(HasInitClient client) {
        super(client);
    }

    @Override
    public void execute(String[] items) throws KrbException {
        if (items.length == 1
            || items.length == 2 && (items[1].startsWith("?") || items[1].startsWith("-help"))) {
            System.out.println(USAGE);
            return;
        }

        HasInitClient client = getClient();
        System.out.println(client.setPlugin(items[1]));
    }
}
