/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kerby.has.server.web.rest;

import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * HAS configure web methods implementation.
 */
@Path("/conf")
public class ConfigApi {

    @Context
    private ServletContext context;

    @Context
    private HttpServletRequest httpRequest;

    /**
     * Set HAS plugin.
     *
     * @param plugin HAS plugin name
     * @return Response
     */
    @PUT
    @Path("/setplugin")
    @Consumes({MediaType.TEXT_PLAIN})
    @Produces({MediaType.TEXT_PLAIN})
    public Response setPlugin(@QueryParam("plugin") final String plugin) {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            WebServer.LOG.info("Set HAS plugin...");
            String msg;
            try {
                Map<String, String> values = new HashMap<>();
                File hasConfFile = new File(hasServer.getConfDir(), "has-server.conf");
                HasConfig hasConfig = HasUtil.getHasConfig(hasConfFile);
                if (hasConfig != null) {
                    String defaultValue = hasConfig.getPluginName();
                    values.put(defaultValue, plugin);
                } else {
                    msg = "has-server.conf not found.";
                    WebServer.LOG.error(msg);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                }
                hasServer.updateConfFile("has-server.conf", values);
            } catch (IOException | HasException e) {
                msg = "Failed to set HAS plugin, because: " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
            msg = "HAS plugin set successfully.";
            WebServer.LOG.info(msg);
            return Response.ok(msg).build();
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * Config HAS server backend.
     *
     * @param backendType type of backend
     * @param dir         json dir
     * @param driver      mysql JDBC connector driver
     * @param url         mysql JDBC connector url
     * @param user        mysql user name
     * @param password    mysql password of user
     * @return Response
     */
    @PUT
    @Path("/configbackend")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.TEXT_PLAIN})
    public Response configBackend(
        @QueryParam("backendType") final String backendType,
        @QueryParam("dir") @DefaultValue("/tmp/has/jsonbackend") final String dir,
        @QueryParam("driver") @DefaultValue("org.drizzle.jdbc.DrizzleDriver") final String driver,
        @QueryParam("url") @DefaultValue("jdbc:mysql:thin://127.0.0.1:3306/mysqlbackend") final String url,
        @QueryParam("user") @DefaultValue("root") final String user,
        @QueryParam("password") @DefaultValue("passwd") final String password) {

        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            String msg;
            if ("json".equals(backendType)) {
                WebServer.LOG.info("Set Json backend...");
                try {
                    Map<String, String> values = new HashMap<>();
                    values.put("_JAR_", "org.apache.kerby.kerberos.kdc.identitybackend.JsonIdentityBackend");
                    values.put("#_JSON_DIR_", "backend.json.dir = " + dir);
                    values.put("#_MYSQL_\n", "");
                    hasServer.updateConfFile("backend.conf", values);
                } catch (IOException | HasException e) {
                    msg = "Failed to set Json backend, because: " + e.getMessage();
                    WebServer.LOG.error(msg);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                }
                msg = "Json backend set successfully.";
                WebServer.LOG.info(msg);
                return Response.ok(msg).build();
            } else if ("mysql".equals(backendType)) {
                WebServer.LOG.info("Set MySQL backend...");
                try {
                    String drizzleUrl = url.replace("jdbc:mysql:", "jdbc:mysql:thin:");
                    String mysqlConfig = "mysql_driver = " + driver + "\nmysql_url = " + drizzleUrl
                        + "\nmysql_user = " + user + "\nmysql_password = " + password;
                    Map<String, String> values = new HashMap<>();
                    values.put("_JAR_", "org.apache.kerby.kerberos.kdc.identitybackend.MySQLIdentityBackend");
                    values.put("#_JSON_DIR_\n", "");
                    values.put("#_MYSQL_", mysqlConfig);
                    hasServer.updateConfFile("backend.conf", values);
                } catch (IOException | HasException e) {
                    msg = "Failed to set MySQL backend, because: " + e.getMessage();
                    WebServer.LOG.error(msg);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                }
                msg = "MySQL backend set successfully.";
                WebServer.LOG.info(msg);
                return Response.ok(msg).build();
            } else {
                msg = backendType + " is not supported.";
                WebServer.LOG.info(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * Config HAS server KDC.
     * @param port KDC port to set
     * @param realm KDC realm to set
     * @param host KDC host to set
     * @return Response
     */
    @PUT
    @Path("/configkdc")
    @Consumes({MediaType.TEXT_PLAIN})
    @Produces({MediaType.TEXT_PLAIN})
    public Response configKdc(
        @QueryParam("port") final int port,
        @QueryParam("realm") final String realm,
        @QueryParam("host") final String host) {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            WebServer.LOG.info("Config HAS server KDC...");
            String msg;
            try {
                BackendConfig backendConfig = KdcUtil.getBackendConfig(hasServer.getConfDir());
                String backendJar = backendConfig.getString("kdc_identity_backend");
                if (backendJar.equals("org.apache.kerby.kerberos.kdc.identitybackend.MySQLIdentityBackend")) {
                    hasServer.configMySQLKdc(backendConfig, realm, port, host, hasServer);
                } else {
                    Map<String, String> values = new HashMap<>();
                    values.put("_HOST_", host);
                    values.put("_PORT_", String.valueOf(port));
                    values.put("_REALM_", realm);
                    hasServer.updateConfFile("kdc.conf", values);
                    String kdc = "\t\tkdc = " + host + ":" + port;
                    values.put("_KDCS_", kdc);
                    values.put("_UDP_LIMIT_", "4096");
                    hasServer.updateConfFile("krb5.conf", values);
                }
            } catch (IOException | HasException | KrbException e) {
                msg = "Failed to config HAS KDC, because: " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
            msg = "HAS server KDC set successfully.";
            WebServer.LOG.info(msg);
            return Response.ok(msg).build();
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * Get krb5.conf file.
     *
     * @return Response
     */
    @GET
    @Path("/getkrb5conf")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getKrb5Conf() {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            String msg;
            try {
                BackendConfig backendConfig = KdcUtil.getBackendConfig(hasServer.getConfDir());
                String backendJar = backendConfig.getString("kdc_identity_backend");
                File conf;
                if (backendJar.equals("org.apache.kerby.kerberos.kdc.identitybackend.MySQLIdentityBackend")) {
                    conf = hasServer.generateKrb5Conf();
                } else {
                    File confDir = hasServer.getConfDir();
                    conf = new File(confDir, "krb5.conf");
                }
                return Response.ok(conf).header("Content-Disposition", "attachment; filename=krb5.conf").build();
            } catch (KrbException | HasException e) {
                msg = "Failed to get Krb5.conf, because: " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * Get has-client.conf file.
     *
     * @return Response
     */
    @GET
    @Path("/gethasclientconf")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getHasConf() {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            String msg;
            try {
                BackendConfig backendConfig = KdcUtil.getBackendConfig(hasServer.getConfDir());
                String backendJar = backendConfig.getString("kdc_identity_backend");
                File conf;
                if (backendJar.equals("org.apache.kerby.kerberos.kdc.identitybackend.MySQLIdentityBackend")) {
                    conf = hasServer.generateHasConf();
                } else {
                    File confDir = hasServer.getConfDir();
                    conf = new File(confDir, "has-server.conf");
                }
                return Response.ok(conf).header("Content-Disposition", "attachment; filename=has-client.conf").build();
            } catch (IOException | KrbException | HasException e) {
                msg = "Failed to get has-client.conf, because: " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }
}
