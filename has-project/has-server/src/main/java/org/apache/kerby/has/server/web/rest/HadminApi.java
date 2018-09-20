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

import org.apache.hadoop.http.JettyUtils;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.has.server.admin.LocalHadmin;
import org.apache.kerby.has.server.web.HostRoleType;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.kerby.has.server.web.rest.param.HostParam;
import org.apache.kerby.has.server.web.rest.param.HostRoleParam;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONObject;

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
 * HAS Admin web methods implementation.
 */
@Path("/hadmin")
public class HadminApi {

    @Context
    private ServletContext context;

    @Context
    private HttpServletRequest httpRequest;

    private void compressFile(File file, ZipOutputStream out, String basedir) throws HasException {
        if (!file.exists()) {
            return;
        }
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            ZipEntry entry = new ZipEntry(basedir + file.getName());
            out.putNextEntry(entry);
            int count;
            byte[] data = new byte[8192];
            while ((count = bis.read(data, 0, 8192)) != -1) {
                out.write(data, 0, count);
            }
            bis.close();
        } catch (Exception e) {
            throw new HasException(e.getMessage());
        }
    }

    @PUT
    @Path("/addprincipalsbyrole")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addprincipalsbyrole(@Context HttpServletRequest request) {
        if (httpRequest.isSecure()) {
            LocalHadmin hasAdmin = null;
            try {
                hasAdmin = new LocalHadmin(WebServer.getHasServerFromContext(context));
            } catch (KrbException e) {
                String error = "Failed to create local hadmin." + e.getMessage();
                WebServer.LOG.error(error);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
            }

            JSONArray results = new JSONArray();
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
                        List<String> strs = hasAdmin.addPrincByRole(host.getString("name"), role.toUpperCase());
                        for (String str : strs) {
                            results.put(str);
                        }
                    }
                }
                return Response.ok(results.toString()).build();
            } catch (Exception e) {
                WebServer.LOG.error("Failed to create principals, because : " + e.getMessage());
                String error = "Failed to create principals, because : " + e.getMessage();
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    /**
     * @param host Hadoop node
     * @param role Hadoop role
     * @return Response
     */
    @GET
    @Path("/exportKeytabsbyrole")
    @Produces(MediaType.TEXT_PLAIN)
    public Response exportKeytabsbyrole(@QueryParam(HostParam.NAME) @DefaultValue(HostParam.DEFAULT)
                                  final HostParam host,
                                  @QueryParam(HostRoleParam.NAME) @DefaultValue(HostRoleParam.DEFAULT)
                                  final HostRoleParam role) {
        if (httpRequest.isSecure()) {
            WebServer.LOG.info("Request to export keytabs.");
            String msg;
            LocalHadmin hasAdmin;
            HasServer hasServer;
            try {
                hasServer = WebServer.getHasServerFromContext(context);
                hasAdmin = new LocalHadmin(hasServer);
            } catch (KrbException e) {
                msg = "Failed to create local hadmin." + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
            if (host.getValue() != null) {
                if (role.getValue() != null) {
                    try {
                        File file = hasAdmin.getKeytabByHostAndRole(host.getValue(), role.getValue());
                        if (file.length() == 0) {
                            msg = "Failed to get the keytab from backend, cannot find matching keytab, "
                                    + "please check hostname and role.";
                            WebServer.LOG.error(msg);
                            return Response.status(Response.Status.BAD_REQUEST).entity(msg).build();
                        }
                        WebServer.LOG.info("Create keytab file for the " + role.getValue()
                                + " for " + host.getValue());
                        return Response.ok(file).header("Content-Disposition",
                                "attachment; filename=" + role.getValue() + "-"
                                        + host.getValue() + ".keytab").build();
                    } catch (HasException e) {
                        msg = "Failed to export keytab File because : " + e.getMessage();
                        WebServer.LOG.error(msg);
                        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                    }
                } else {
                    //export keytabs zip file
                    List<File> keytabs = new ArrayList<>();
                    for (HostRoleType r : HostRoleType.values()) {
                        try {
                            File keytab = hasAdmin.getKeytabByHostAndRole(host.getValue(), r.getName());
                            if (keytab.length() > 0) {
                                keytabs.add(hasAdmin.getKeytabByHostAndRole(host.getValue(), r.getName()));
                                WebServer.LOG.info("Create keytab file for the " + r.getName()
                                        + " for " + host.getValue());
                            }
                        } catch (HasException e) {
                            msg = "Failed to export keytab File because : " + e.getMessage();
                            WebServer.LOG.error(msg);
                            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                        }
                    }
                    if (keytabs.size() < 1) {
                        msg = "Failed to get the keytab from backend, cannot find matching keytab, "
                                + "please check hostname.";
                        WebServer.LOG.error(msg);
                        return Response.status(Response.Status.BAD_REQUEST).entity(msg).build();
                    }
                    File path = new File(hasServer.getWorkDir(), "tmp/zip/"
                        + System.currentTimeMillis());
                    path.mkdirs();
                    File keytabZip = new File(path, "keytab.zip");
                    if (keytabZip.exists()) {
                        keytabZip.delete();
                    }
                    try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(keytabZip))) {
                        for (File keytab : keytabs) {
                            compressFile(keytab, zos, "");
                        }
                        zos.close();
                        WebServer.LOG.info("Success to create the keytab.zip.");
                        return Response.ok(keytabZip).header("Content-Disposition",
                            "attachment; filename=keytab.zip").build();
                    } catch (Exception e) {
                        msg = "Failed to create the keytab.zip, because : " + e.getMessage();
                        WebServer.LOG.error(msg);
                        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
                    }
                }
            } else {
                msg = "The host value is empty.";
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.BAD_REQUEST).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    @GET
    @Path("/hostroles")
    @Produces(MediaType.APPLICATION_JSON + ";" + JettyUtils.UTF_8)
    public Response getRoles() {
        if (httpRequest.isSecure()) {
            JSONArray result = new JSONArray();
            try {
                for (HostRoleType role : HostRoleType.values()) {
                    JSONObject json = new JSONObject();
                    json.put("HostRole", role.getName());
                    JSONArray jsa = new JSONArray();
                    String[] princs = role.getPrincs();
                    for (String princ : princs) {
                        jsa.put(princ);
                    }
                    json.put("PrincipalNames", jsa);
                    result.put(json);
                }
                return Response.ok(result.toString() + "\n").build();
            } catch (Exception e) {
                String msg = "Failed to get host roles." + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
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
            String result;
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
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }
}
