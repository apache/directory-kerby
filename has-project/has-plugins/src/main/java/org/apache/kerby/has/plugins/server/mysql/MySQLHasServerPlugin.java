/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.plugins.server.mysql;

import org.apache.commons.dbutils.DbUtils;
import org.apache.kerby.has.server.AbstractHasServerPlugin;
import org.apache.kerby.has.server.HasAuthenException;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.ResultSet;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.Date;

public class MySQLHasServerPlugin extends AbstractHasServerPlugin {
    private static final Logger LOG = LoggerFactory.getLogger(MySQLHasServerPlugin.class);

     /**
     * {@inheritDoc}
     */
    @Override
    public String getLoginType() {
        return "MySQL";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void doAuthenticate(AuthToken userToken, AuthToken authToken)
        throws HasAuthenException {

        // Check if the token is expired
        Date expiredTime = userToken.getExpiredTime();
        Date now = new Date();
        if (now.after(expiredTime)) {
            LOG.error("Authentication failed: token is expired.");
            throw new HasAuthenException("Authentication failed: token is expired.");
        }

        String user = (String) userToken.getAttributes().get("user");
        String secret = (String) userToken.getAttributes().get("secret");

        String mysqlUrl = System.getenv("mysqlUrl");
        mysqlUrl = mysqlUrl.replace("jdbc:mysql:", "jdbc:mysql:thin:");
        String mysqlUser = System.getenv("mysqlUser");
        String mysqlPasswd = System.getenv("mysqlPasswd");
        Connection connection = startConnection(mysqlUrl, mysqlUser, mysqlPasswd);

        ResultSet res = null;
        PreparedStatement preStm = null;
        try {
            String stm = "SELECT COUNT(*) FROM `has_user` WHERE user_name = ? AND pass_word = ?";
            preStm = connection.prepareStatement(stm);
            preStm.setString(1, user);
            preStm.setString(2, secret);
            res = preStm.executeQuery();
            if (res.next() && res.getInt(1) > 0) {
              LOG.debug("UserName: " + user);
            } else {
                LOG.error("Authentication failed.");
                throw new HasAuthenException("Authentication failed.");
            }
        } catch (SQLException e) {
            LOG.error("Failed.");
            LOG.error("Error code: " + e.getErrorCode());
            LOG.error("Error message: " + e.getMessage());
            throw new HasAuthenException("Authentication failed." + e.getMessage());
        } finally {
            DbUtils.closeQuietly(preStm);
            DbUtils.closeQuietly(res);
            DbUtils.closeQuietly(connection);
        }

        authToken.setIssuer(userToken.getIssuer());
        authToken.setSubject(user);
        authToken.setExpirationTime(userToken.getExpiredTime());

        authToken.addAttribute("userName", user);
        authToken.addAttribute("passPhrase", user + secret);
    }

    /**
     * Start the MySQL connection.
     */
    private Connection startConnection(String url, String user,
                                       String password) throws HasAuthenException {
        Connection connection;
        try {
            Class.forName("org.drizzle.jdbc.DrizzleDriver");
            connection = DriverManager.getConnection(url, user, password);
            if (!connection.isClosed()) {
                LOG.info("Succeeded in connecting to MySQL.");
            }
        } catch (ClassNotFoundException e) {
            throw new HasAuthenException("JDBC Driver Class not found. ", e);
        } catch (SQLException e) {
            throw new HasAuthenException("Failed to connecting to MySQL. ", e);
        }

        return connection;
    }
}
