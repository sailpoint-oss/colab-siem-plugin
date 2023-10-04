package com.sailpoint.siem.rest;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sailpoint.siem.db.SIEMAccess;
import com.sailpoint.siem.object.AppValuesDTO;
import com.sailpoint.siem.object.IdentityValuesDTO;
import com.sailpoint.siem.object.SIEMConstants;

import sailpoint.integration.ListResult;
import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;

/**
 * @author adam.creaney (Created on 4/17/17).
 *
 */
@Path("SIEMPlugin")
@Produces("application/json")
@AllowAll
public class DashboardService extends BasePluginResource {
	
	public static final Log log = LogFactory.getLog(DashboardService.class);
	
	@Override
	public String getPluginName() {
		
		return SIEMConstants.PLUGIN_NAME;
	}
	
	/**
	 * Gets an instance of the SIEMAlertService.
	 *
	 * @return The service.
	 */
	private SIEMAccess getSIEMAccess() {
		
		return new SIEMAccess(this);
	}
	
	@GET
	@Path("dashboardService/AlertDatesService/{timeInterval}/{isDays}")
	public ListResult getAlertDatesService(@PathParam("timeInterval") int timeInterval,
			@PathParam("isDays") boolean isDays) {
		
		log.debug("Entering getAlertDatesService...");
		
		List<AppValuesDTO> alertdateList = new ArrayList<>();
		try {
			
			SIEMAccess sac = getSIEMAccess();
			alertdateList = sac.getAlertsByDate(timeInterval, isDays);
			
		} catch (Exception e) {
			
			log.error("Error in getAlertDatesService: " + e.getMessage());
		}
		
		log.debug("Exiting getAlertDatesService...");
		return new ListResult(alertdateList, alertdateList.size());
	}
	
	@GET
	@Path("dashboardService/IdentityCountService")
	public ListResult getIdentityCountService() {
		
		log.debug("Entering getIdentityCountService...");
		
		// String identityCounts = null;
		List<IdentityValuesDTO> identityCountsList = new ArrayList<>();
		try {
			
			SIEMAccess sac = getSIEMAccess();
			identityCountsList = sac.getIdentities(10);
			// log.debug("Identity size: " + identitycountsList.size());
			
		} catch (Exception e) {
			
			log.error("Error in getIdentityCountService: " + e);
		}
		
		log.debug("Exiting getIdentityCountService...");
		return new ListResult(identityCountsList, identityCountsList.size());
	}
}
