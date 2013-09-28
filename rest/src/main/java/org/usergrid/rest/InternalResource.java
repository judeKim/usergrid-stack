/*******************************************************************************
 * Copyright 2013 baas.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package org.usergrid.rest;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.usergrid.utils.JsonUtils.mapToJsonString;

import java.net.URISyntaxException;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import com.google.common.collect.BiMap;
import com.sun.jersey.api.json.JSONWithPadding;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;
import org.usergrid.management.ApplicationInfo;
import org.usergrid.management.OrganizationInfo;
import org.usergrid.rest.exceptions.OrganizationApplicationNotFoundException;
import org.usergrid.rest.management.organizations.OrganizationResource;
import org.usergrid.rest.security.annotations.RequireSystemAccess;
import org.usergrid.rest.utils.PathingUtils;
import org.usergrid.security.oauth.AccessInfo;

/**
 * @author jude Kim(i.judekim@gmail.com)
 */
@Path("/internal")
@Component
@Scope("singleton")
@Produces({MediaType.APPLICATION_JSON, "application/javascript",
        "application/x-javascript", "text/ecmascript",
        "application/ecmascript", "text/jscript"})
public class InternalResource extends AbstractContextResource {

    private static final Logger logger = LoggerFactory.getLogger(InternalResource.class);

    public InternalResource() {
        logger.info("InternalResource initialized");
    }

    @RequireSystemAccess
    @GET
    @Path("organizations")
    public JSONWithPadding getAllOrganizations(
            @Context UriInfo ui,
            @QueryParam("callback") @DefaultValue("callback") String callback) throws URISyntaxException {
        ApiResponse response = new ApiResponse();
        response.setAction("get organizations");
        try {
            BiMap orgs = management.getOrganizations();
            response.setProperty("organizations", orgs.inverse());
            response.setSuccess();
        } catch (Exception e) {
            logger.info("Unable to retrieve organizations", e);
        }
        return new JSONWithPadding(response, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("orgs")
    public JSONWithPadding getAllOrganizations2(
            @Context UriInfo ui,
            @QueryParam("callback") @DefaultValue("callback") String callback) throws URISyntaxException {
        return getAllOrganizations(ui, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("organizations/{organizationId: [A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}}")
    public JSONWithPadding getOrganizationByUuid(
            @Context UriInfo ui,
            @PathParam("organizationId") String organizationIdString,
            @QueryParam("callback") @DefaultValue("callback") String callback) throws Exception {
        UUID orgId = UUID.fromString(organizationIdString);
        OrganizationInfo organization = management.getOrganizationByUuid(orgId);
        OrganizationResource organizationResource = getSubResource(OrganizationResource.class).init(organization);
        return organizationResource.getOrganizationDetails(ui, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("orgs/{organizationId: [A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}}")
    public JSONWithPadding getOrganizationByUuid2(
            @Context UriInfo ui,
            @PathParam("organizationId") String organizationIdString,
            @QueryParam("callback") @DefaultValue("callback") String callback) throws Exception {
        return getOrganizationByUuid(ui, organizationIdString, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("organizations/{organizationName}")
    public JSONWithPadding getOrganizationByName(
            @Context UriInfo ui,
            @PathParam("organizationName") String organizationName,
            @QueryParam("callback") @DefaultValue("callback") String callback) throws Exception {
        OrganizationInfo organization = management.getOrganizationByName(organizationName);
        OrganizationResource organizationResource = getSubResource(OrganizationResource.class).init(organization);
        return organizationResource.getOrganizationDetails(ui, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("orgs/{organizationName}")
    public JSONWithPadding getOrganizationByName2(
            @Context UriInfo ui,
            @PathParam("organizationName") String organizationName,
            @QueryParam("callback") @DefaultValue("callback") String callback) throws Exception {
        return getOrganizationByName(ui, organizationName, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("applications")
    public JSONWithPadding getAllApplications(
            @Context UriInfo ui,
            @QueryParam("callback") @DefaultValue("callback") String callback) throws URISyntaxException {
        ApiResponse response = createApiResponse();
        response.setAction("get applications");
        Map<String, UUID> applications;
        try {
            applications = emf.getApplications();
            response.setSuccess();
            response.setApplications(applications);
        } catch (Exception e) {
            logger.info("Unable to retrieve applications", e);
        }
        return new JSONWithPadding(response, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("apps")
    public JSONWithPadding getAllApplications2(
            @Context UriInfo ui,
            @QueryParam("callback") @DefaultValue("callback") String callback) throws URISyntaxException {
        return getAllApplications(ui, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("token/{organizationName}")
    public Response getAccessTokenForOrgByName(
            @Context UriInfo ui,
            @PathParam("organizationName") String organizationName,
            @QueryParam("callback") @DefaultValue("") String callback) throws Exception {
        return getAccessTokenByName(ui, organizationName, null, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("token/{organizationId: [A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}}")
    public Response getAccessTokenForOrgByUuid(
            @Context UriInfo ui,
            @PathParam("organizationId") String organizationId,
            @QueryParam("callback") @DefaultValue("") String callback) throws Exception {
        return getAccessTokenByUuid(ui, organizationId, null, callback);
    }

    @RequireSystemAccess
    @GET
    @Path("token/{organizationName}/{applicationName}")
    public Response getAccessTokenByName(
            @Context UriInfo ui,
            @PathParam("organizationName") String organizationName,
            @PathParam("applicationName") String applicationName,
            @QueryParam("callback") @DefaultValue("") String callback) throws Exception {

        if (StringUtils.isNotEmpty(applicationName)) {
            String orgAppName = PathingUtils.assembleAppName(organizationName, applicationName);
            return getAccessTokenByUuid(ui, null, emf.lookupApplication(orgAppName).toString(), callback);
        } else {
            OrganizationInfo organizationInfo = management.getOrganizationByName(organizationName);
            if (organizationInfo == null) {
                throw new OrganizationApplicationNotFoundException(organizationName, ui, properties);
            }
            return getAccessTokenByUuid(ui, organizationInfo.getUuid().toString(), null, callback);
        }
    }

    @RequireSystemAccess
    @GET
    @Path("token/{organizationId: [A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}}/{applicationId: [A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}}")
    public Response getAccessTokenByUuid(
            @Context UriInfo ui,
            @PathParam("organizationId") String organizationId,
            @PathParam("applicationId") String applicationId,
            @QueryParam("callback") @DefaultValue("") String callback) throws Exception {

        UUID applicationUuid = null;
        UUID organizationUuid = null;

        if (organizationId != null) {
            organizationUuid = UUID.fromString(organizationId);
        }
        if (applicationId != null) {
            applicationUuid = UUID.fromString(applicationId);
        }

        String clientId;
        String clientSecret;
        if (StringUtils.isNotEmpty(applicationId)) {
            ApplicationInfo applicationInfo = management.getApplicationInfo(applicationUuid);
            if (applicationInfo == null) {
                throw new OrganizationApplicationNotFoundException(applicationId, ui, properties);
            }

            clientId = management.getClientIdForApplication(applicationUuid);
            clientSecret = management.getClientSecretForApplication(applicationUuid);
        } else {
            OrganizationInfo organizationInfo = management.getOrganizationByUuid(organizationUuid);
            if (organizationInfo == null) {
                throw new OrganizationApplicationNotFoundException(applicationId, ui, properties);
            }
            clientId = management.getClientIdForOrganization(organizationUuid);
            clientSecret = management.getClientSecretForOrganization(organizationUuid);
        }

        AccessInfo access_info = management.authorizeClient(clientId, clientSecret, 0);
        if (access_info != null) {
            return Response.status(SC_OK).type(jsonMediaType(callback))
                    .entity(wrapWithCallback(access_info, callback))
                    .build();
        }

        return Response.status(SC_BAD_REQUEST).type(jsonMediaType(callback))
                .build();
    }

    private static String wrapWithCallback(AccessInfo accessInfo,
                                           String callback) {
        return wrapWithCallback(mapToJsonString(accessInfo), callback);
    }

    private static String wrapWithCallback(String json, String callback) {
        if (StringUtils.isNotBlank(callback)) {
            json = callback + "(" + json + ")";
        }
        return json;
    }

    private static MediaType jsonMediaType(String callback) {
        return isNotBlank(callback) ? new MediaType("application", "javascript")
                : APPLICATION_JSON_TYPE;
    }
}