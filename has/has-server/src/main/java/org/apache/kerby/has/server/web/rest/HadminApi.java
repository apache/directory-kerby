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

import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.has.server.admin.LocalHasAdmin;
import org.apache.kerby.has.server.web.HostRoleType;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.kerby.has.server.web.rest.param.HostParam;
import org.apache.kerby.has.server.web.rest.param.HostRoleParam;
import org.apache.kerby.has.server.web.rest.param.PasswordParam;
import org.apache.kerby.has.server.web.rest.param.PrincipalParam;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * HAS HasAdmin web methods implementation.
 */
@Path("/admin")
public class HadminApi {

    @Context
    private ServletContext context;

    @Context
    private HttpServletRequest httpRequest;

    private void compressFile(File file, ZipOutputStream out, String basedir) {
        if (!file.exists()) {
            return;
        }
        try {
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
            ZipEntry entry = new ZipEntry(basedir + file.getName());
            out.putNextEntry(entry);
            int count;
            byte[] data = new byte[8192];
            while ((count = bis.read(data, 0, 8192)) != -1) {
                out.write(data, 0, count);
            }
            bis.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @param host Hadoop node
     * @param role Hadoop role
     * @return Response
     */
    @GET
    @Path("/exportkeytabs")
    @Produces(MediaType.TEXT_PLAIN)
    public Response exportKeytabs(@QueryParam(HostParam.NAME) @DefaultValue(HostParam.DEFAULT)
                                  final HostParam host,
                                  @QueryParam(HostRoleParam.NAME) @DefaultValue(HostRoleParam.DEFAULT)
                                  final HostRoleParam role) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to export keytabs.");
            LocalHasAdmin hasAdmin = null;
            HasServer hasServer = null;
            try {
                hasServer = WebServer.getHasServerFromContext(context);
                hasAdmin = new LocalHasAdmin(hasServer);
            } catch (KrbException e) {
                WebServer.LOG.info("Failed to create local hadmin." + e.getMessage());
            }
            if (host.getValue() != null) {
                if (role.getValue() != null) {
                    try {
                        File file = hasAdmin.getKeytabByHostAndRole(host.getValue(), role.getValue());
                        WebServer.LOG.info("Create keytab file for the " + role.getValue()
                            + " for " + host.getValue());
                        return Response.ok(file).header("Content-Disposition",
                            "attachment; filename=" + role.getValue() + "-"
                                + host.getValue() + ".keytab").build();
                    } catch (HasException e) {
                        WebServer.LOG.error("Failed to export keytab File because : " + e.getMessage());
                    }
                } else {
                    //export keytabs zip file
                    List<File> keytabs = new ArrayList<>();
                    for (HostRoleType r : HostRoleType.values()) {
                        try {
                            keytabs.add(hasAdmin.getKeytabByHostAndRole(host.getValue(), r.getName()));
                            WebServer.LOG.info("Create keytab file for the " + r.getName()
                                + " for " + host.getValue());
                        } catch (HasException e) {
                            WebServer.LOG.info("Failed to export keytab File because : " + e.getMessage());
                        }
                    }
                    if (keytabs.size() < 1) {
                        return Response.serverError().build();
                    }
                    File path = new File(hasServer.getWorkDir(), "tmp/zip/"
                        + System.currentTimeMillis());
                    path.mkdirs();
                    File keytabZip = new File(path, "keytab.zip");
                    if (keytabZip.exists()) {
                        keytabZip.delete();
                    }
                    try {
                        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(keytabZip));
                        for (File keytab : keytabs) {
                            compressFile(keytab, zos, "");
                        }
                        zos.close();
                        WebServer.LOG.info("Success to create the keytab.zip.");
                        return Response.ok(keytabZip).header("Content-Disposition",
                            "attachment; filename=keytab.zip").build();
                    } catch (Exception e) {
                        WebServer.LOG.error("Failed to create the keytab.zip,because : " + e.getMessage());
                    }
                }
            }
            return Response.serverError().build();
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }

    /**
     * export single keytab file
     *
     * @param principal principal name to export keytab file
     * @return Response
     */
    @GET
    @Path("/exportkeytab")
    @Produces(MediaType.TEXT_PLAIN)
    public Response exportKeytab(@QueryParam("principal") final String principal) {
        if (httpRequest.isSecure()) {
            LocalHasAdmin hasAdmin = null;
            WebServer.LOG.info("Exporting keytab file for " + principal + "...");
            try {
                HasServer hasServer = WebServer.getHasServerFromContext(context);
                hasAdmin = new LocalHasAdmin(hasServer);
            } catch (KrbException e) {
                WebServer.LOG.error("Failed to create local hadmin." + e.getMessage());
            }
            WebServer.LOG.info("Create keytab file for " + principal + " successfully.");
            if (principal != null) {
                try {
                    File path = new File("/tmp/" + System.currentTimeMillis());
                    if (path.mkdirs()) {
                        File keytabFile = new File(path, principal + ".keytab");
                        hasAdmin.exportKeytab(keytabFile, principal);
                        return Response.ok(keytabFile).header("Content-Disposition", "attachment; filename="
                            + keytabFile.getName()).build();
                    }
                } catch (HasException e) {
                    WebServer.LOG.error("Failed to export keytab. " + e.toString());
                    return Response.serverError().build();
                }
            }
            return Response.serverError().build();
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }

    @PUT
    @Path("/setconf")
    @Produces(MediaType.APPLICATION_JSON)
    public Response setConf(@QueryParam("isEnable") String isEnable) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to admin/setconf.");
            final HasServer hasServer = WebServer.getHasServerFromContext(
                context);
            File hasConf = new File(hasServer.getConfDir(), "has-server.conf");
            if (!hasConf.exists()) {
                WebServer.LOG.error("has-server.conf is not exists.");
                return Response.serverError().entity("has-server.conf is not exists.")
                    .build();
            }
            String result = "";
            if (isEnable.equals("true")) {
                result = "enable";
            } else if (isEnable.equals("false")) {
                result = "disable";
            } else {
                WebServer.LOG.error("Value of isEnable is error.");
                return Response.serverError().entity("Value of isEnable is error.")
                    .build();
            }
            try {
                HasUtil.setEnableConf(hasConf, isEnable);
            } catch (Exception e) {
                WebServer.LOG.error(e.getMessage());
                return Response.serverError().entity(e.getMessage()).build();
            }
            return Response.ok("Set conf to " + result).build();
        }
        return Response.status(403).entity("HTTPS required.\n").build();
    }

    @GET
    @Path("/getprincipals")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getprincipals(@QueryParam("exp") String exp) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to get principals.");
            JSONObject result = new JSONObject();
            String msg;
            LocalHasAdmin hasAdmin = null;
            try {
                hasAdmin = new LocalHasAdmin(WebServer.getHasServerFromContext(context));
            } catch (KrbException e) {
                WebServer.LOG.info("Failed to create local hadmin." + e.getMessage());
            }
            try {
                JSONArray principals = new JSONArray();
                List<String> princList = hasAdmin.getPrincipals(exp);
                for (String princ : princList) {
                    principals.put(princ);
                }
                WebServer.LOG.info("Success to get principals with JSON.");
                result.put("result", "success");
                result.put("msg", principals.toString());
                return Response.ok(result.toString()).build();
            } catch (Exception e) {
                WebServer.LOG.error("Failed to get principals,because : " + e.getMessage());
                msg = "Failed to get principals,because : " + e.getMessage();
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
     * Add principal by name and password.
     *
     * @param principal principal name.
     * @param password  principal password
     * @return Response
     */
    @POST
    @Path("/addprincipal")
    @Produces(MediaType.TEXT_PLAIN)
    public Response addprincipal(@QueryParam(PrincipalParam.NAME) @DefaultValue(PrincipalParam.DEFAULT)
                                 final PrincipalParam principal,
                                 @QueryParam(PasswordParam.NAME) @DefaultValue(PasswordParam.DEFAULT)
                                 final PasswordParam password) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to add the principal named " + principal.getValue());
            LocalHasAdmin hasAdmin = null;
            try {
                hasAdmin = new LocalHasAdmin(WebServer.getHasServerFromContext(context));
            } catch (KrbException e) {
                WebServer.LOG.info("Failed to create local hadmin." + e.getMessage());
            }
            JSONObject result = new JSONObject();
            String msg = "Add principal successfully.";
            try {
                hasAdmin.addPrincipal(principal.getValue(), password.getValue());
                result.put("result", "success");
                result.put("msg", msg);
                return Response.ok(result.toString()).build();
            } catch (Exception e) {
                WebServer.LOG.error("Failed to add " + principal + " principal, because: " + e.getMessage());
                msg = "Failed to add " + principal + " principal, because: " + e.getMessage();
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

    @POST
    @Path("/renameprincipal")
    @Produces(MediaType.TEXT_PLAIN)
    public Response renamePrincipal(@QueryParam("oldprincipal") String oldPrincipal,
                                    @QueryParam("newprincipal") String newPrincipal) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to rename " + oldPrincipal + " to " + newPrincipal);
            JSONObject result = new JSONObject();
            String msg = "Rename principal successfully.";
            if (oldPrincipal != null && newPrincipal != null) {
                LocalHasAdmin hasAdmin = null;
                try {
                    hasAdmin = new LocalHasAdmin(WebServer.getHasServerFromContext(context));
                } catch (KrbException e) {
                    WebServer.LOG.info("Failed to create local hadmin." + e.getMessage());
                }
                try {
                    hasAdmin.renamePrincipal(oldPrincipal, newPrincipal);
                    result.put("result", "success");
                    result.put("msg", msg);
                    return Response.ok(result.toString()).build();
                } catch (Exception e) {
                    WebServer.LOG.error("Failed to rename principal " + oldPrincipal + " to "
                        + newPrincipal + ",because: " + e.getMessage());
                    msg = "Failed to rename principal " + oldPrincipal + " to "
                        + newPrincipal + ",because: " + e.getMessage();
                }
            } else {
                WebServer.LOG.error("Value of old or new principal is null.");
                msg = "Value of old or new principal is null.";
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
     * Delete principal by name.
     *
     * @param principal principal like "admin" or "admin@HADOOP.COM".
     * @return Response
     */
    @DELETE
    @Path("/deleteprincipal")
    @Produces(MediaType.TEXT_PLAIN)
    public Response deleteprincipal(@QueryParam(PrincipalParam.NAME) @DefaultValue(PrincipalParam.DEFAULT)
                                    final PrincipalParam principal) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to delete the principal named " + principal.getValue());
            JSONObject result = new JSONObject();
            String msg = "Delete principal successfully.";
            LocalHasAdmin hasAdmin = null;
            try {
                hasAdmin = new LocalHasAdmin(WebServer.getHasServerFromContext(context));
            } catch (KrbException e) {
                WebServer.LOG.info("Failed to create local hadmin." + e.getMessage());
            }
            try {
                hasAdmin.deletePrincipal(principal.getValue());
                result.put("result", "success");
                result.put("msg", msg);
                return Response.ok(result.toString()).build();
            } catch (Exception e) {
                WebServer.LOG.error("Failed to delete the principal named " + principal.getValue()
                    + ",because : " + e.getMessage());
                msg = "Failed to delete the principal named " + principal.getValue()
                    + ",because : " + e.getMessage();
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

    @PUT
    @Path("/createprincipals")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createprincipals(@Context HttpServletRequest request) {
        if (httpRequest.isSecure()) {
            LocalHasAdmin hasAdmin = null;
            try {
                hasAdmin = new LocalHasAdmin(WebServer.getHasServerFromContext(context));
            } catch (KrbException e) {
                WebServer.LOG.info("Failed to create local hadmin." + e.getMessage());
            }
            JSONObject result = new JSONObject();
            String msg = "";
            try {
                StringBuilder data = new StringBuilder();
                BufferedReader br = new BufferedReader(new InputStreamReader(request.getInputStream()));
                String s;
                while ((s = br.readLine()) != null) {
                    data.append(s);
                }
                WebServer.LOG.info("Request to create principals by JSON : \n" + data.toString());
                JSONArray hostArray = new JSONObject(data.toString()).optJSONArray("HOSTS");
                for (int i = 0; i < hostArray.length(); i++) {
                    JSONObject host = (JSONObject) hostArray.get(i);
                    String[] roles = host.getString("hostRoles").split(",");
                    for (String role : roles) {
                        msg += hasAdmin.addPrincByRole(host.getString("name"), role.toUpperCase());
                    }
                }
                result.put("result", "success");
                result.put("msg", msg);
                return Response.ok(result.toString()).build();
            } catch (Exception e) {
                WebServer.LOG.error("Failed to create principals,because : " + e.getMessage());
                msg = "Failed to create principals,because : " + e.getMessage();
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
}
