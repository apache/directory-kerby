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

import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.kerby.has.server.web.rest.param.PasswordParam;
import org.apache.kerby.has.server.web.rest.param.PrincipalParam;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcSetting;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONObject;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.Consumes;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.util.List;
import java.util.Map;

/**
 * Kadmin web methods implementation.
 */
@Path("/kadmin")
public class KadminApi {
    @Context
    private ServletContext context;

    @Context
    private HttpServletRequest httpRequest;

    /**
     * export single keytab file
     *
     * @param principal principal name to export keytab file
     * @param isGlobal string to represent if current export principal is in global mode
     * @return Response
     */
    @GET
    @Path("/exportkeytab")
    @Produces(MediaType.TEXT_PLAIN)
    public Response exportKeytab(@QueryParam("principal") final String principal,
                                 @QueryParam("global") @DefaultValue("false")
                                 final String isGlobal) {
        boolean global = false;
        String globalModeVlue = "true";
        if (globalModeVlue.equals(isGlobal)) {
            global = true;
        }
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Exporting keytab file for " + principal + "...");
            String msg;
            LocalKadminImpl localKadmin;
            HasServer hasServer = WebServer.getHasServerFromContext(context);
            KdcSetting serverSetting = hasServer.getKdcServer().getKdcSetting();
            try {
                localKadmin = new LocalKadminImpl(serverSetting);
            } catch (KrbException e) {
                msg = "Failed to create local kadmin." + e.getMessage();
                WebServer.LOG.info(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
            if (principal != null) {
                if (global) {
                    // principal is a pattern expression
                    List<String> princList;
                    try {
                        princList = localKadmin.getPrincipals(principal);
                        WebServer.LOG.info("Success to get principals with JSON.");
                    } catch (Exception e) {
                        msg = "Failed to get principals,because : " + e.getMessage();
                        WebServer.LOG.error(msg);
                        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                    }
                    if (princList.size() != 0) {
                        WebServer.LOG.info("Exporting keytab file for " + principal + "...");
                        File path = new File("/tmp/" + System.currentTimeMillis());
                        if (path.mkdirs()) {
                            File keytabFile = new File(path, principal.replace('/', '-')
                                                                            .replace('*', '-')
                                                                            .replace('?', '-')
                                            + ".keytab");
                            try {
                                localKadmin.exportKeytab(keytabFile, princList);
                                WebServer.LOG.info("Create keytab file for principals successfully.");
                                return Response.ok(keytabFile).header("Content-Disposition",
                                        "attachment; filename=" + keytabFile.getName()).build();
                            } catch (KrbException e) {
                                msg = "Failed to export keytab. " + e.toString();
                                WebServer.LOG.error(msg);
                                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                            }
                        }
                    } else {
                        msg = "No matched principals.";
                        WebServer.LOG.error(msg);
                        return Response.status(Response.Status.BAD_REQUEST).entity(msg).build();
                    }
                } else {
                    File path = new File("/tmp/" + System.currentTimeMillis());
                    if (path.mkdirs()) {
                        File keytabFile = new File(path, principal.replace('/', '-') + ".keytab");
                        try {
                            localKadmin.exportKeytab(keytabFile, principal);
                            WebServer.LOG.info("Create keytab file for " + principal + " successfully.");
                            return Response.ok(keytabFile).header(
                                "Content-Disposition", "attachment; filename="
                                    + keytabFile.getName()).build();
                        } catch (KrbException e) {
                            msg = "Failed to export keytab. " + e.toString();
                            WebServer.LOG.error(msg);
                            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                        }
                    }
                }
            }
            return Response.serverError().build();
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    @GET
    @Path("/listprincipals")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listPrincipals(@QueryParam("exp") String exp) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to get principals.");
            String msg;
            LocalKadminImpl localKadmin;
            HasServer hasServer = WebServer.getHasServerFromContext(context);
            KdcSetting serverSetting = hasServer.getKdcServer().getKdcSetting();
            try {
                localKadmin = new LocalKadminImpl(serverSetting);
            } catch (KrbException e) {
                msg = "Failed to create local kadmin." + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
            try {
                JSONArray principals = new JSONArray();
                List<String> princList = localKadmin.getPrincipals(exp);
                for (String princ : princList) {
                    principals.put(princ);
                }
                WebServer.LOG.info("Success to get principals with JSON.");
                return Response.ok(principals.toString()).build();
            } catch (Exception e) {
                msg = "Failed to get principals,because : " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * Add principal by name and password.
     *
     * @param principal principal name.
     * @param password principal password
     * @return Response
     */
    @POST
    @Path("/addprincipal")
    @Produces(MediaType.TEXT_PLAIN)
    public Response addPrincipal(@QueryParam(PrincipalParam.NAME) @DefaultValue(PrincipalParam.DEFAULT)
                                 final PrincipalParam principal,
                                 @QueryParam(PasswordParam.NAME) @DefaultValue(PasswordParam.DEFAULT)
                                 final PasswordParam password) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to add the principal named " + principal.getValue());
            String msg;
            LocalKadminImpl localKadmin;
            HasServer hasServer = WebServer.getHasServerFromContext(context);
            KdcSetting serverSetting = hasServer.getKdcServer().getKdcSetting();
            try {
                localKadmin = new LocalKadminImpl(serverSetting);
            } catch (KrbException e) {
                msg = "Failed to create local kadmin." + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
            if (principal.getValue() == null) {
                msg = "Value of principal is null.";
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.BAD_REQUEST).entity(msg).build();
            }
            if (password.getValue() == null || password.getValue().equals("")) {
                try {
                    localKadmin.addPrincipal(principal.getValue());
                    msg = "Add principal successfully.";
                    return Response.ok(msg).build();
                } catch (KrbException e) {
                    msg = "Failed to add " + principal + " principal, because: " + e.getMessage();
                    WebServer.LOG.error(msg);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                }
            } else {
                try {
                    localKadmin.addPrincipal(principal.getValue(), password.getValue());
                    msg = "Add principal successfully.";
                    return Response.ok(msg).build();
                } catch (KrbException e) {
                    msg = "Failed to add " + principal + " principal, because: " + e.getMessage();
                    WebServer.LOG.error(msg);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                }
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    @POST
    @Path("/renameprincipal")
    @Produces(MediaType.TEXT_PLAIN)
    public Response renamePrincipal(@QueryParam("oldprincipal") String oldPrincipal,
                                    @QueryParam("newprincipal") String newPrincipal) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to rename " + oldPrincipal + " to " + newPrincipal);
            String msg;
            if (oldPrincipal != null && newPrincipal != null) {
                LocalKadminImpl localKadmin;
                HasServer hasServer = WebServer.getHasServerFromContext(context);
                KdcSetting serverSetting = hasServer.getKdcServer().getKdcSetting();
                try {
                    localKadmin = new LocalKadminImpl(serverSetting);
                } catch (KrbException e) {
                    msg = "Failed to create local kadmin." + e.getMessage();
                    WebServer.LOG.info(msg);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                }

                try {
                    localKadmin.renamePrincipal(oldPrincipal, newPrincipal);
                    msg = "Rename principal successfully.";
                    return Response.ok(msg).build();
                } catch (Exception e) {
                    msg = "Failed to rename principal " + oldPrincipal + " to "
                            + newPrincipal + ",because: " + e.getMessage();
                    WebServer.LOG.error(msg);
                    return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                }
            } else {
                msg = "Value of old or new principal is null.";
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.NOT_FOUND).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * Delete principal by name.
     *
     * @param principal principal like "admin" or "admin@HADOOP.COM".
     * @return Response
     */
    @DELETE
    @Path("/deleteprincipal")
    @Produces(MediaType.TEXT_PLAIN)
    public Response deletePrincipal(@QueryParam(PrincipalParam.NAME) @DefaultValue(PrincipalParam.DEFAULT)
                                    final PrincipalParam principal) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to delete the principal named " + principal.getValue());
            String msg;
            LocalKadminImpl localKadmin;
            HasServer hasServer = WebServer.getHasServerFromContext(context);
            KdcSetting serverSetting = hasServer.getKdcServer().getKdcSetting();
            try {
                localKadmin = new LocalKadminImpl(serverSetting);
            } catch (KrbException e) {
                msg = "Failed to create local kadmin." + e.getMessage();
                WebServer.LOG.info(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }

            try {
                localKadmin.deletePrincipal(principal.getValue());
                msg = "Delete principal successfully.";
                return Response.ok(msg).build();
            } catch (Exception e) {
                msg = "Failed to delete the principal named " + principal.getValue()
                        + ",because : " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * change password.
     *
     * @param principal principal name.
     * @param newPassword  principal new password
     * @return Response
     */
    @POST
    @Path("/changepassword")
    @Produces(MediaType.TEXT_PLAIN)
    public Response changePassword(@QueryParam(PrincipalParam.NAME) @DefaultValue(PrincipalParam.DEFAULT)
                                   final PrincipalParam principal,
                                   @QueryParam(PasswordParam.NAME) @DefaultValue(PasswordParam.DEFAULT)
                                   final PasswordParam newPassword) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to add the principal named " + principal.getValue());
            String msg;
            LocalKadminImpl localKadmin;
            HasServer hasServer = WebServer.getHasServerFromContext(context);
            KdcSetting serverSetting = hasServer.getKdcServer().getKdcSetting();
            try {
                localKadmin = new LocalKadminImpl(serverSetting);
            } catch (KrbException e) {
                msg = "Failed to create local kadmin." + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
            if (principal.getValue() == null || principal.getValue().isEmpty()) {
                msg = "Value of principal is null.";
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.BAD_REQUEST).entity(msg).build();
            }
            if (newPassword.getValue() == null || newPassword.getValue().isEmpty()) {
                msg = "Value of new password is null.";
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.BAD_REQUEST).entity(msg).build();
            }
            try {
                localKadmin.changePassword(principal.getValue(), newPassword.getValue());
                msg = "Change password successfully.";
                return Response.ok(msg).build();
            } catch (KrbException e) {
                msg = "Failed to change the password of " + principal.getValue()
                        + " , because: " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * Get principal by name.
     *
     * @param principal principal like "admin" or "admin@HADOOP.COM".
     * @return Response
     */
    @POST
    @Path("/getprincipal")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPrincipal(@QueryParam(PrincipalParam.NAME) @DefaultValue(PrincipalParam.DEFAULT)
                                 final PrincipalParam principal) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to get a principal named " + principal.getValue());
            String msg;
            LocalKadminImpl localKadmin;
            HasServer hasServer = WebServer.getHasServerFromContext(context);
            KdcSetting serverSetting = hasServer.getKdcServer().getKdcSetting();
            try {
                localKadmin = new LocalKadminImpl(serverSetting);
            } catch (KrbException e) {
                msg = "Failed to create local kadmin. " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }

            try {
                KrbIdentity identity = localKadmin.getPrincipal(principal.getValue());
                // put single identity in object to send back to client
                JSONObject principle = new JSONObject();
                Map<EncryptionType, EncryptionKey> key = identity.getKeys();
                principle.put("Name", identity.getPrincipalName());
                principle.put("Expiration date", identity.getExpireTime());
                principle.put("Created time", identity.getCreatedTime());
                principle.put("KDC flags", identity.getKdcFlags());
                principle.put("Key version", identity.getKeyVersion());
                principle.put("Number of keys", key.size());
                JSONObject keySet = new JSONObject();
                int keyCount = 0;
                for (EncryptionType keyType : key.keySet()) {
                    keySet.put(String.valueOf(keyCount++), keyType);
                }
                principle.put("Keys", keySet);
                WebServer.LOG.info("Success to get principal with JSON.");

                return Response.ok(principle).build();
            } catch (Exception e) {
                msg = "Failed to get principal,because : " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }
}

