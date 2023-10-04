package com.sailpoint.siem.rest;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sailpoint.siem.object.SIEMConstants;
import com.sailpoint.siem.rest.helper.SIEMExtResourceHelper;

import sailpoint.plugin.PluginBaseHelper;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.rest.plugin.RequiredRight;
import sailpoint.tools.GeneralException;

/**
 * @author prashant.kagwad (Created on 2/19/20).
 *
 */
@Path("SIEMPlugin")
@RequiredRight("siemextadministrator")
public class SIEMExtResource extends BasePluginResource {
	
	public static final Log log = LogFactory.getLog(SIEMExtResource.class);
	
	@Override
	public String getPluginName() {
		
		return SIEMConstants.PLUGIN_NAME;
	}
	
	@GET
	@Path("syslog-events")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getSyslogEvents(@QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
			@QueryParam("startTime") String startTime, @QueryParam("endTime") String endTime,
			@QueryParam("quickKey") String quickKey) throws GeneralException {
		
		log.trace("Entering getSyslogEvents...");
		
		// Get the limit set in manifest.
		int manifestLimit = PluginBaseHelper.getSettingInt(SIEMConstants.PLUGIN_NAME, SIEMConstants.SYSLOG_LIMIT);
		
		log.trace("Exiting getSyslogEvents...");
		return SIEMExtResourceHelper.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
	}
	
	@GET
	@Path("audit-events")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getAuditEvents(@QueryParam("startIndex") String startIndex, @QueryParam("count") String count,
			@QueryParam("startTime") String startTime, @QueryParam("endTime") String endTime,
			@QueryParam("type") String type) throws GeneralException {
		
		log.trace("Entering getAuditEvents...");
		
		// Get the limit set in manifest.
		int manifestLimit = PluginBaseHelper.getSettingInt(SIEMConstants.PLUGIN_NAME, SIEMConstants.AUDIT_EVENT_LIMIT);
		
		log.trace("Exiting getAuditEvents...");
		return SIEMExtResourceHelper.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
	}
}
