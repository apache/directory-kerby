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
import org.apache.kerby.has.server.HasServer;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.kerby.kerberos.kerb.KrbException;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;

/**
 * HAS initialize methods implementation.
 */
@Path("/init")
public class InitApi {

    @Context
    private ServletContext context;

    @Context
    private HttpServletRequest httpRequest;

    @GET
    @Path("/kdcinit")
    @Produces(MediaType.TEXT_PLAIN)
    public Response kdcInit() {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            String msg;
            try {
                File adminKeytab = hasServer.initKdcServer();
                return Response.ok(adminKeytab).header("Content-Disposition",
                    "attachment; filename=" + adminKeytab.getName()).build();
            } catch (KrbException e) {
                msg = "Failed to initialize KDC, because: " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }

    @GET
    @Path("/kdcstart")
    @Produces(MediaType.TEXT_PLAIN)
    public Response kdcStart() {
        if (httpRequest.isSecure()) {
            final HasServer hasServer = WebServer.getHasServerFromContext(context);
            String msg;
            try {
                hasServer.startKdcServer();
                msg = "Succeed in starting KDC server.";
                WebServer.LOG.info(msg);
                return Response.ok(msg).build();
            } catch (HasException e) {
                msg = "Failed to start kdc server, because: " + e.getMessage();
                WebServer.LOG.error(msg);
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(msg).build();
            }
        }
        return Response.status(Response.Status.FORBIDDEN).entity("HTTPS required.\n").build();
    }
}
