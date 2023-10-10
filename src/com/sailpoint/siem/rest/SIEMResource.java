package com.sailpoint.siem.rest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;

import com.sailpoint.siem.db.SIEMAlertService;
import com.sailpoint.siem.db.SIEMOverviewDataService;
import com.sailpoint.siem.object.AuditActionDTO;
import com.sailpoint.siem.object.ResponseDTO;
import com.sailpoint.siem.object.SIEMAlertDTO;
import com.sailpoint.siem.object.SIEMConstants;
import com.sailpoint.siem.util.SIEMUtil;

import sailpoint.api.SailPointContext;
import sailpoint.api.SailPointFactory;
import sailpoint.object.Application;
import sailpoint.object.AuditConfig;
import sailpoint.object.AuditConfig.AuditAction;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.rest.plugin.RequiredRight;
import sailpoint.tools.GeneralException;

/**
 * @author adam.creaney (Created on 4/17/17).
 *
 */
@Path("SIEMPlugin")
@RequiredRight("siemadministrator")
public class SIEMResource extends BasePluginResource {
	
	public static final Log log = LogFactory.getLog(SIEMResource.class);
	
	@Override
	public String getPluginName() {
		
		return SIEMConstants.PLUGIN_NAME;
	}
	
	@GET
	@Path("plainTextHello")
	public String getPlainTextHello() {
		
		return SIEMConstants.DEFAULT_WELCOME_MESSAGE;
	}
	
	@POST
	@Path("identity")
	public String postIdentity() {
		
		log.debug("POST identity");
		// TODO : this does nothing???
		return null;
	}
	
	/**
	 * Function to get an instance of the SIEMAlertService.
	 *
	 * @return The service.
	 */
	private SIEMAlertService getAlertService() {
		
		return new SIEMAlertService(this);
	}
	
	@POST
	@Path("identity/account")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityAccount(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityAccount...");
		
		// YP - Incase if we need to use it in future.
		// authorize(new SIEMAuthorizer(data));
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error("Missing necessary parameters or value for REST service : " + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_ACCOUNT, false);
		
		log.trace("Exiting postIdentityAccount...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("identity/accounts")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityAccounts(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityAccounts...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_ACCOUNTS, false);
		
		log.trace("Exiting postIdentityAccounts...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("identity/entitlement")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityEntitlement(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityEntitlement...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY_ENTITLEMENT);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_ENTITLEMENT, true);
		
		log.trace("Exiting postIdentityEntitlement...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("identity/entitlements")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityEntitlements(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityEntitlements...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_ENTITLEMENTS, false);
		
		log.trace("Exiting postIdentityEntitlements...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("identity/entitlements-all")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityEntitlementsAll(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityEntitlementsAll...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_ENTITLEMENTS_ALL, false);
		
		log.trace("Exiting postIdentityEntitlementsAll...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("identity/password")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityPassword(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityPassword...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_PASSWORD, false);
		
		log.trace("Exiting postIdentityPassword...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("identity/passwords")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityPasswords(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityPasswords...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_PASSWORDS, false);
		
		log.trace("Exiting postIdentityPasswords...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("identity/certify")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityCertify(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityCertify...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_CERTIFY, false);
		
		log.trace("Exiting postIdentityCertify...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("identity/certify-all")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postIdentityCertifyAll(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postIdentityCertifyAll...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.IDENTITY);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.IDENTITY_CERTIFY_ALL, false);
		
		log.trace("Exiting postIdentityCertifyAll...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("application/group")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postApplicationGroups(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postApplicationGroups...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.APPLICATION_GROUP);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.APPLICATION_GROUP, true);
		
		log.trace("Exiting postApplicationGroups...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("application/accounts")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postApplicationAccounts(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postApplicationAccounts...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.APPLICATION_ACCOUNTS);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.APPLICATION_ACCOUNTS, true);
		
		log.trace("Exiting postApplicationAccounts...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("application/certify-group")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postApplicationCertifyGroup(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postApplicationCertifyGroup...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.APPLICATION_CERTIFY_GROUP);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.APPLICATION_CERTIFY_GROUP, true);
		
		log.trace("Exiting postApplicationCertifyGroup...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	@POST
	@Path("application/certify-all")
	@Produces(MediaType.APPLICATION_JSON)
	public Response postApplicationCertifyAll(Map<String, String> data) throws GeneralException {
		
		log.trace("Entering postApplicationCertifyAll...");
		
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.APPLICATION_CERTIFY_ALL);
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, ""))
					.build();
		}
		
		String siemAlertId = createSIEMAlertFromData(data, SIEMConstants.APPLICATION_CERTIFY_ALL, false);
		
		log.trace("Exiting postApplicationCertifyAll...");
		return Response.status(Response.Status.OK).entity(
				new ResponseDTO(SIEMConstants.RESPONSE_STATUS_SUCCESS, SIEMConstants.MSG_CREATED_ALERT_ID, siemAlertId))
				.build();
	}
	
	/**
	 * Gets a list of currently configured applications in IdentityIQ
	 *
	 * @return - JSON containing all configured application names
	 */
	@GET
	@Path("applications")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getApplications() throws GeneralException, JSONException {
		
		log.trace("Entering getApplications...");
		
		List<String> apps = new ArrayList<>();
		SailPointContext context = SailPointFactory.getCurrentContext();
		
		List<Application> appList = context.getObjects(Application.class);
		for (int itr = 0; itr < appList.size(); itr++) {
			
			Application app = appList.get(itr);
			apps.add(app.getName());
		}
		
		log.trace("Exiting getApplications...");
		return Response.status(Response.Status.OK).entity(apps).build();
	}
	
	/**
	 * Gets a list of currently configured applications in IdentityIQ
	 * 
	 * @param data
	 *            - The account names, or native identifiers to check
	 * @return
	 * @throws GeneralException
	 * @throws JSONException
	 */
	@POST
	@Path("identityinfo")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getIdentityInfo(Map<String, String> data) throws GeneralException, JSONException {
		
		log.trace("Entering postIdentityInfo...");
		
		Object ret = null;
		String validationAttrs = SIEMUtil.validateAttributes(data, SIEMConstants.SIEM_IDENTITY_INFO);
		
		if (!validationAttrs.equalsIgnoreCase(SIEMConstants.SUCCESS)) {
			
			log.error(SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs);
			return Response.status(Response.Status.BAD_REQUEST)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							SIEMConstants.MSG_MISSING_PARAMETERS + validationAttrs, "Error - check system logs."))
					.build();
		} else {
			
			log.debug("Valid request...");
			ret = SIEMUtil.getIdentityInfo(getContext(), data);
		}
		
		//
		// if (log.isDebugEnabled()) {
		// log.debug("The identity info is: " + ret);
		// }
		
		log.trace("Exiting postIdentityInfo...");
		return Response.status(Response.Status.OK).entity(ret).build();
	}
	
	/**
	 * Following logic is implemented based off the inputs :
	 * 
	 * 1. name = null and enabled = false - return all AuditActions.
	 * 
	 * 2. name = null and enabled = true - return all AuditActions that are enabled.
	 * 
	 * 3. name = foo and enabled = false - return only one AuditActions with name
	 * foo if found, else exception.
	 * 
	 * 4. name = foo and enabled = true - return only one AuditActions with name foo
	 * if found, else exception.
	 */
	
	@GET
	@Path("auditConfiguration")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getAuditConfiguration(@QueryParam("name") String name,
			@DefaultValue("false") @QueryParam("enabled") boolean enabled) throws GeneralException {
		
		// log.trace("Entering getAuditConfiguration for name: " + name + ", isenabled:
		// " + enabled);
		
		Object response = null;
		// Get auditConfig object.
		SailPointContext context = SailPointFactory.getCurrentContext();
		AuditConfig auditConfig = context.getObjectByName(AuditConfig.class, SIEMConstants.AUDIT_CONFIG);
		List<AuditAction> auditActionList = auditConfig.getActions();
		
		// To hold list of AuditActions if not querying for a specific AuditAction.
		// [Case 1 & 2]
		List<AuditActionDTO> auditActionArray = new ArrayList<>();
		
		// To hold the specified AuditAction. [Case 3 & 4]
		AuditActionDTO queriedAuditAction = new AuditActionDTO();
		
		try {
			
			boolean isPresent = false;
			for (AuditAction auditAction : auditActionList) {
				
				AuditActionDTO tempAuditAction = new AuditActionDTO(auditAction.getName(), auditAction.isEnabled());
				
				// Check if AuditAction exists, if yes then just return. [Case 3 & 4]
				if (null != name && !name.isEmpty() && name.equalsIgnoreCase(auditAction.getName())) {
					
					isPresent = true;
					queriedAuditAction.setName(auditAction.getName());
					queriedAuditAction.setEnabled(auditAction.isEnabled());
					break;
				}
				
				// Check only enabled AuditActions. [Case 1 & 2]
				if (enabled) {
					
					if (auditAction.isEnabled()) {
						
						auditActionArray.add(tempAuditAction);
					}
				} else {
					
					auditActionArray.add(tempAuditAction);
				}
			}
			
			// Based on the name, either return the list or single AuditAction if found.
			if (null == name || name.isEmpty()) {
				
				// [Case 1 & 2]
				// auditEvents.put(SIEMConstants.AUDIT_EVENTS, auditActionArray);
				response = auditActionArray;
			} else {
				
				if (isPresent) {
					
					// auditEvents.put(SIEMConstants.AUDIT_EVENTS, queriedAuditAction);
					response = queriedAuditAction;
				} else {
					
					return Response.status(Response.Status.BAD_REQUEST)
							.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
									"AuditAction " + name + " not found.", ""))
							.build();
				}
			}
		} catch (Exception e) {
			
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
					.entity(new ResponseDTO(SIEMConstants.RESPONSE_STATUS_ERROR,
							"Something went wrong while building the json.", e.getMessage()))
					.build();
		}
		
		log.trace("Exiting getAuditConfiguration...");
		return Response.status(Response.Status.OK).entity(response).build();
	}
	
	/**
	 * Function to fill out a CreateAlertData object from the data in the map.
	 *
	 * @param data
	 *            The Map<String, String>.
	 * @return The alert create data.
	 * @throws GeneralException
	 */
	private String createSIEMAlertFromData(Map<String, String> data, String type, boolean isGroup)
			throws GeneralException {
		
		log.trace("Entering createSIEMAlertFromData...");
		
		SIEMAlertDTO alertData = new SIEMAlertDTO();
		alertData.setNativeId(data.get(SIEMConstants._NATIVE_ID));
		alertData.setCreated(Long.parseLong(data.get(SIEMConstants.DATE)));
		alertData.setSourceApplication(data.get(SIEMConstants.APPLICATION));
		alertData.setLevel(data.get(SIEMConstants.LEVEL));
		alertData.setAlertType(type);
		alertData.setAction(data.get(SIEMConstants.ACTION));
		
		if (isGroup) {
			
			alertData.setTargetGroupName(data.get(SIEMConstants._GROUP_NAME));
			alertData.setTargetGroupType(data.get(SIEMConstants._GROUP_TYPE));
		}
		
		alertData.setIsOverride(Boolean.parseBoolean(data.get(SIEMConstants._USE_WORKFLOW)));
		
		// YP - The SIEMAlertService will set this field with the ID retrieved from the
		// sailpoint alert object
		// alertData.setAlertId(id);
		// YP - The SIEMAlertService will set this field when the alert is processed
		// alertData.setProcessed_date(new Date().getTime());
		
		SIEMAlertService siemAlertService = getAlertService();
		SIEMAlertDTO siemAlert = siemAlertService.createSIEMAlert(alertData);
		SIEMOverviewDataService siemOverviewDataService = new SIEMOverviewDataService(this);
		siemOverviewDataService.updateSiemMetrics(siemAlert);
		
		log.trace("Exiting createSIEMAlertFromData...");
		return siemAlert.getId();
	}
}
