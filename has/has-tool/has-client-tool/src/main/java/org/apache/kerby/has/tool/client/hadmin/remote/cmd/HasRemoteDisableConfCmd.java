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
package org.apache.kerby.has.tool.client.hadmin.remote.cmd;

import org.apache.kerby.has.client.HasAdminClient;
import org.apache.kerby.has.client.HasAuthAdminClient;
import org.apache.kerby.has.common.HasException;

/**
 * Remote add principal cmd
 */
public class HasRemoteDisableConfCmd extends HadminRemoteCmd {

    public static final String USAGE = "Usage: disable_configure\n"
            + "\tExample:\n"
            + "\t\tdisable\n";

    public HasRemoteDisableConfCmd(HasAdminClient hadmin, HasAuthAdminClient authHadmin) {
        super(hadmin, authHadmin);
    }

    @Override
    public void execute(String[] items) throws HasException {
        HasAdminClient hasAdminClient;
        if (getAuthHadmin() != null) {
            hasAdminClient = getAuthHadmin();
        } else {
            hasAdminClient = getHadmin();
        }
        hasAdminClient.setEnableOfConf("false");
    }
}
