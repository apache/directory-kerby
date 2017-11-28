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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.HasAuthenException;
import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.has.server.HasServerPlugin;
import org.apache.kerby.has.server.HasServerPluginRegistry;
import org.apache.kerby.has.server.kdc.HasKdcHandler;
import org.apache.kerby.has.server.web.HostRoleType;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.kerby.has.server.web.rest.param.AuthTokenParam;
import org.apache.kerby.has.server.web.rest.param.TypeParam;
import org.apache.hadoop.http.JettyUtils;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
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
import java.util.Map;
import java.util.TreeMap;

/**
 * HAS web methods implementation.
 */
@Path("")
public class HasApi {

    @Context
    private ServletContext context;

    @Context
    private HttpServletRequest httpRequest;

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
            try {
                BackendConfig backendConfig = KdcUtil.getBackendConfig(hasServer.getConfDir());
                String backendJar = backendConfig.getString("kdc_identity_backend");
                File conf;
                if (backendJar.equals("org.apache.kerby.has.server.kdc.MySQLIdentityBackend")) {
                    conf = hasServer.generateKrb5Conf();
                } else {
                    File confDir = hasServer.getConfDir();
                    conf = new File(confDir, "krb5.conf");
                }
                return Response.ok(conf).header("Content-Disposition", "attachment; filename=krb5.conf").build();
            } catch (KrbException | HasException e) {
                throw new RuntimeException("Failed to get Krb5.conf. ", e);
            }
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }

    /**
     * Get has-client.conf file.
     *
     * @return Response
     */
    @GET
    @Path("/gethasconf")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getHasConf() {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            try {
                BackendConfig backendConfig = KdcUtil.getBackendConfig(hasServer.getConfDir());
                String backendJar = backendConfig.getString("kdc_identity_backend");
                File conf;
                if (backendJar.equals("org.apache.kerby.has.server.kdc.MySQLIdentityBackend")) {
                    conf = hasServer.generateHasConf();
                } else {
                    File confDir = hasServer.getConfDir();
                    conf = new File(confDir, "has-server.conf");
                }
                return Response.ok(conf).header("Content-Disposition", "attachment; filename=has-client.conf").build();
            } catch (IOException | KrbException | HasException e) {
                throw new RuntimeException("Failed to get has-client.conf. ", e);
            }
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }

    /**
     * Get CA file.
     *
     * @return Response
     */
    @GET
    @Path("/getcert")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getCert() {
        final HasServer hasServer = WebServer.getHasServerFromContext(context);
        String errMessage = null;
        File cert = null;
        try {
            HasConfig hasConfig = HasUtil.getHasConfig(
                new File(hasServer.getConfDir(), "has-server.conf"));
            if (hasConfig != null) {
                String certPath = hasConfig.getSslClientCert();
                cert = new File(certPath);
                if (!cert.exists()) {
                    errMessage = "Cert file not found in HAS server.";
                    WebServer.LOG.error("Cert file not found in HAS server.");
                }
            } else {
                errMessage = "has-server.conf not found.";
                WebServer.LOG.error("has-server.conf not found.");
            }
        } catch (HasException e) {
            errMessage = "Failed to get cert file" + e.getMessage();
            WebServer.LOG.error("Failed to get cert file" + e.getMessage());
        }
        if (errMessage == null) {
            return Response.ok(cert).header("Content-Disposition",
                "attachment;filename=" + cert.getName()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).entity(errMessage).build();
        }
    }

    @GET
    @Path("/hostroles")
    @Produces(MediaType.APPLICATION_JSON + ";" + JettyUtils.UTF_8)
    public Response getRoles() {
        if (httpRequest.isSecure()) {
            JSONArray result = new JSONArray();
            try {
                for (HostRoleType role : HostRoleType.values()) {
                    JSONObject jso = new JSONObject();
                    jso.put("HostRole", role.getName());
                    JSONArray jsa = new JSONArray();
                    String[] princs = role.getPrincs();
                    for (String princ : princs) {
                        jsa.put(princ);
                    }
                    jso.put("PrincipalNames", jsa);
                    result.put(jso);
                }
                return Response.ok(result.toString() + "\n").type(MediaType.APPLICATION_JSON).build();
            } catch (Exception e) {
                WebServer.LOG.error("Failed to get host roles." + e.getMessage());
            }
            return Response.serverError().build();
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }

    @GET
    @Path("/kdcinit")
    @Produces(MediaType.TEXT_PLAIN)
    public Response kdcInit() {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            try {
                File adminKeytab = hasServer.initKdcServer();
                return Response.ok(adminKeytab).header("Content-Disposition",
                    "attachment; filename=" + adminKeytab.getName()).build();
            } catch (KrbException e) {
                System.err.println("[ERROR] " + e.getMessage());
            }
            return Response.serverError().build();
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }

    @GET
    @Path("/kdcstart")
    @Produces(MediaType.TEXT_PLAIN)
    public Response kdcStart() {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            JSONObject result = new JSONObject();
            String msg = "Succeed in starting KDC server.";

            try {
                hasServer.startKdcServer();
            } catch (HasException e) {
                WebServer.LOG.error("Fail to start kdc server. " + e.getMessage());
                msg = e.getMessage();
            }
            try {
                result.put("result", "success");
                result.put("msg", msg);
                return Response.ok(result.toString()).build();
            } catch (Exception e) {
                WebServer.LOG.error(e.getMessage());
                msg = e.getMessage();
            }
            try {
                result.put("result", "error");
                result.put("msg", msg);
            } catch (JSONException e) {
                WebServer.LOG.error(e.getMessage());
            }
            return Response.ok(result.toString()).build();
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }

    /**
     * Handle HTTP PUT request.
     */
    @PUT
    @Produces({MediaType.APPLICATION_OCTET_STREAM + "; " + JettyUtils.UTF_8,
        MediaType.APPLICATION_JSON + "; " + JettyUtils.UTF_8})
    public Response asRequest(
        @QueryParam(TypeParam.NAME) @DefaultValue(TypeParam.DEFAULT)
        final TypeParam type,
        @QueryParam(AuthTokenParam.NAME) @DefaultValue(AuthTokenParam.DEFAULT)
        final AuthTokenParam authToken
    ) {
        return asRequest(type.getValue(), authToken.getValue());
    }

    private Response asRequest(String type, String tokenStr) {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            String errMessage = null;
            String js = null;
            ObjectMapper mapper = new ObjectMapper();
            final Map<String, Object> m = new TreeMap<String, Object>();

            if (hasServer.getKdcServer() == null) {
                errMessage = "Please start the has KDC server.";
            } else if (!tokenStr.isEmpty() && tokenStr != null) {
                HasKdcHandler kdcHandler = new HasKdcHandler(hasServer);

                TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

                AuthToken authToken = null;
                try {
                    authToken = tokenDecoder.decodeFromString(tokenStr);
                } catch (IOException e) {
                    errMessage = "Failed to decode the token string." + e.getMessage();
                    WebServer.LOG.error(errMessage);
                }
                HasServerPlugin tokenPlugin = null;
                try {
                    tokenPlugin = HasServerPluginRegistry.createPlugin(type);
                } catch (HasException e) {
                    errMessage = "Fail to get the plugin: " + type + ". " + e.getMessage();
                    WebServer.LOG.error(errMessage);
                }
                AuthToken verifiedAuthToken;
                try {
                    verifiedAuthToken = tokenPlugin.authenticate(authToken);
                } catch (HasAuthenException e) {
                    errMessage = "Failed to verify auth token: " + e.getMessage();
                    WebServer.LOG.error(errMessage);
                    verifiedAuthToken = null;
                }

                if (verifiedAuthToken != null) {
                    KrbMessage asRep = kdcHandler.getResponse(verifiedAuthToken,
                        (String) verifiedAuthToken.getAttributes().get("passPhrase"));

                    Base64 base64 = new Base64(0);
                    try {
                        m.put("type", tokenPlugin.getLoginType());
                        m.put("success", "true");
                        m.put("krbMessage", base64.encodeToString(asRep.encode()));
                    } catch (IOException e) {
                        errMessage = "Failed to encode KrbMessage." + e.getMessage();
                        WebServer.LOG.error(errMessage);
                    }

                }
            } else {
                errMessage = "The token string should not be empty.";
                WebServer.LOG.error(errMessage);
            }

            if (errMessage != null) {
                m.put("success", "false");
                m.put("krbMessage", errMessage);
            }
            try {
                js = mapper.writeValueAsString(m);
            } catch (JsonProcessingException e) {
                WebServer.LOG.error("Failed write values to string." + e.getMessage());
            }
            return Response.ok(js).type(MediaType.APPLICATION_JSON).build();
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }
}
