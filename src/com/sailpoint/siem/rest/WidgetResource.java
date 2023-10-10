package com.sailpoint.siem.rest;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sailpoint.siem.db.SIEMAccess;
import com.sailpoint.siem.db.SIEMOverviewDataService;
import com.sailpoint.siem.object.AlertDataDTO;
import com.sailpoint.siem.object.SIEMAlertDTO;
import com.sailpoint.siem.object.SIEMConstants;

import sailpoint.api.SailPointContext;
import sailpoint.api.SailPointFactory;
import sailpoint.object.Alert;
import sailpoint.object.Attributes;
import sailpoint.object.Filter;
import sailpoint.object.QueryOptions;
import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;

/**
 * @author unknown
 *
 */
@Path("SIEMPlugin")
@Produces("application/json")
@AllowAll
public class WidgetResource extends BasePluginResource {
	
	public static final Log log = LogFactory.getLog(WidgetResource.class);
	
	@Override
	public String getPluginName() {
		
		return SIEMConstants.PLUGIN_NAME;
	}
	
	/**
	 * Function to get an instance of the SIEMAlertService.
	 *
	 * @return The service.
	 */
	private SIEMAccess getSIEMAccess() {
		
		return new SIEMAccess(this);
	}
	
	@GET
	@Path("widget-service/alerts/{alertType}")
	public Response getAlertType(@PathParam("alertType") String alertType) {
		
		log.trace("Entering getAlertType...");
		
		List<SIEMAlertDTO> alertList = new ArrayList<>();
		Response response;
		
		try {
			
			log.debug("Get alerts...");
			SIEMAccess siemAccess = getSIEMAccess();
			alertList = siemAccess.getAlertType(alertType.replace('-', '/'));
			
			Gson gson = new Gson();
			Type type = new TypeToken<List<SIEMAlertDTO>>() {}.getType();
			String alertJson = gson.toJson(alertList, type);
			
			response = Response.status(Response.Status.OK).entity(alertJson).build();
		} catch (Exception e) {
			
			log.error("Error in getAlertType : " + e);
			response = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
					.entity("Error retrieving alerts, please check logs for more details").build();
		}
		
		log.trace("Exiting getAlertType...");
		return response;
	}
	
	@SuppressWarnings("rawtypes")
	@GET
	@Path("widget-service/alerts/identity/{identityId}")
	public Response getAlertByIdentity(@PathParam("identityId") String identityId) {
		
		log.trace("Entering getAlertByIdentity...");
		
		List<Alert> alertList = new ArrayList<>();
		Response response;
		
		try {
			
			log.debug("Get alerts by identity...");
			
			SailPointContext sailPointContext = SailPointFactory.getCurrentContext();
			
			QueryOptions query = new QueryOptions();
			Filter targetFilter = Filter.eq(SIEMConstants.FILTER_TARGET_ID, identityId);
			Filter typeFilter = Filter.eq(SIEMConstants.FILTER_TYPE, SIEMConstants.SIEM_ALERT);
			Filter filter = Filter.and(targetFilter, typeFilter);
			query.add(filter);
			
			alertList = sailPointContext.getObjects(Alert.class, query);
			log.debug("Alert list size : " + alertList.size());
			
			List<Attributes> attributesList = new ArrayList<>();
			for (Alert alert : alertList) {
				
				alert.setAttribute(SIEMConstants.CREATED, alert.getCreated());
				attributesList.add(alert.getAttributes());
			}
			
			Gson gson = new Gson();
			Type type = new TypeToken<List<Attributes>>() {}.getType();
			String alertJson = gson.toJson(attributesList, type);
			
			response = Response.status(Response.Status.OK).entity(alertJson).build();
		} catch (Exception e) {
			
			log.error("Error in getAlertByIdentity : " + e);
			response = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
					.entity("Error retrieving alerts, please check logs for more details").build();
		}
		
		log.trace("Exiting getAlertByIdentity...");
		return response;
	}
	
	@GET
	@Path("widget-service/alerts/count/{countType}")
	public Response getAlertCount(@PathParam("countType") String countType) {
		
		log.trace("Entering getAlertCount...");
		
		List<AlertDataDTO> alertCountsList;
		Response response;
		
		try {
			
			log.trace("getAlertCount...");
			
			SIEMOverviewDataService siemOverviewDataService = new SIEMOverviewDataService(this);
			alertCountsList = siemOverviewDataService.getAlertCount(countType);
			
			Gson gson = new Gson();
			Type type = new TypeToken<List<AlertDataDTO>>() {}.getType();
			String alertCountJson = gson.toJson(alertCountsList, type);
			response = Response.status(Response.Status.OK).entity(alertCountJson).build();
		} catch (Exception e) {
			
			log.error("Error in getAlertCount: " + e);
			response = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
					.entity("Error retrieving alerts, please check logs for more details").build();
		}
		
		log.trace("Exiting getAlertCount...");
		return response;
	}
}
