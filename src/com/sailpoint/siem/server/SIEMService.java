package com.sailpoint.siem.server;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sailpoint.siem.db.SIEMAlertService;
import com.sailpoint.siem.object.SIEMAlertDTO;
import com.sailpoint.siem.object.SIEMConstants;
import com.sailpoint.siem.util.SIEMUtil;

import sailpoint.api.CertificationScheduler;
import sailpoint.api.IdentityService;
import sailpoint.api.ManagedAttributer;
import sailpoint.api.Provisioner;
import sailpoint.api.RequestManager;
import sailpoint.api.SailPointContext;
import sailpoint.api.Terminator;
import sailpoint.api.Workflower;
import sailpoint.object.Alert;
import sailpoint.object.AlertAction;
import sailpoint.object.AlertAction.AlertNotification;
import sailpoint.object.AlertDefinition;
import sailpoint.object.Application;
import sailpoint.object.Attributes;
import sailpoint.object.AuditEvent;
import sailpoint.object.Certification;
import sailpoint.object.CertificationDefinition;
import sailpoint.object.CertificationSchedule;
import sailpoint.object.Filter;
import sailpoint.object.Identity;
import sailpoint.object.IdentityEntitlement;
import sailpoint.object.Link;
import sailpoint.object.ManagedAttribute;
import sailpoint.object.ProvisioningPlan;
import sailpoint.object.ProvisioningProject;
import sailpoint.object.QueryOptions;
import sailpoint.object.Request;
import sailpoint.object.RequestDefinition;
import sailpoint.object.Rule;
import sailpoint.object.Schema;
import sailpoint.object.WorkflowLaunch;
import sailpoint.persistence.Sequencer;
import sailpoint.server.Auditor;
import sailpoint.server.BasePluginService;
import sailpoint.tools.GeneralException;
import sailpoint.tools.Util;
import sailpoint.tools.xml.XMLObjectFactory;
import sailpoint.tools.xml.XMLReferenceResolver;
import sailpoint.workflow.StandardWorkflowHandler;

/**
 * @author adam.creaney (Created on 4/17/17).
 *
 *         SIEMService Class.
 */
public class SIEMService extends BasePluginService {
	
	public static final Log		log	= LogFactory.getLog(SIEMService.class);
	
	/**
	 * The configured maximum time period for Alert objects.
	 */
	private int					purgeByDays;
	
	/**
	 * Determines whether or not Alerts will be processed in order of priority
	 */
	private boolean				prioritizeByLevel;
	
	/**
	 * Determines whether provisioning will be direct, or done via workflow
	 */
	private boolean				deferProvisioning;
	
	/**
	 * If provisioning is set to workflow, this is the name of the workflow object
	 */
	private String				provisioningWorkflow;
	
	/**
	 * The SIEMAlertService
	 */
	private SIEMAlertService	siemAlertService;
	
	/**
	 * Default Constructor
	 */
	public SIEMService() {
		
		siemAlertService = new SIEMAlertService(this);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getPluginName() {
		
		return SIEMConstants.PLUGIN_NAME;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void configure(SailPointContext context) throws GeneralException {
		
		purgeByDays = getSettingInt(SIEMConstants.PURGE_BY_DAYS);
		prioritizeByLevel = getSettingBool(SIEMConstants.PRIORITIZE_ALERTS);
		deferProvisioning = getSettingBool(SIEMConstants.DEFER_PROVISIONING);
		provisioningWorkflow = getSettingString(SIEMConstants.PROVISIONING_WORKFLOW);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void execute(SailPointContext context) throws GeneralException {
		
		// TODO purge the alert items within purgeAlertItems();
		log.trace("Entering execute...");
		
		createAlerts(context);
		actionAlerts(context);
		pruneAlerts(context);
		
		log.trace("Exiting execute...");
	}
	
	/**
	 * Function to create new IdentityIQ Alert objects from entries in plugin table
	 *
	 * @throws GeneralException
	 */
	public void createAlerts(SailPointContext context) throws GeneralException {
		
		log.trace("Entering createAlerts...");
		
		int count = 0;
		List<SIEMAlertDTO> toCreate = siemAlertService.getNewAlerts(prioritizeByLevel);
		log.debug("The size of toCreate is : " + toCreate.size());
		
		if (toCreate.isEmpty() || toCreate.size() <= 0) {
			return;
		}
		
		Application app = context.getObjectByName(Application.class, SIEMConstants.SIEM_APPLICATION_NAME);
		
		for (SIEMAlertDTO siemAlert : toCreate) {
			
			log.debug("Entering create for alert : " + siemAlert.getId());
			Alert alert = new Alert();
			
			// try and correlate this to an Identity if appropriate
			if (siemAlert.getAlertType().contains(SIEMConstants.IDENTITY)) {
				
				log.debug("Creating an Identity alert, trying to correlate to an Identity object.");
				String identityId = findMatchingIdentityId(context, siemAlert);
				
				if (identityId == null || identityId.isEmpty()) {
					
					log.error("Failure attempting to create Identity SIEM alert with no matching Identity : "
							+ siemAlert.getNativeId());
					// YP: close the alert here so the service doesn't keep picking it up
					Date closeDate = new Date();
					siemAlertService.updateAlertProcessed(siemAlert.getId(), closeDate.getTime());
					continue;
				}
				
				log.debug("Found ID for correlation : " + identityId);
				alert.setTargetId(identityId);
				// TODO : check if we can use constants which are case insensitive
				alert.setTargetType("Identity");
				Identity identity = context.getObjectById(Identity.class, identityId);
				
				if (null != identity) {
					
					alert.setTargetDisplayName(identity.getDisplayableName());
				}
				context.decache(identity);
			}
			
			Attributes<String, Object> attrs = new Attributes<>();
			alert.setAlertDate(new Date(siemAlert.getCreated()));
			alert.setNativeId(siemAlert.getNativeId());
			alert.setSource(app);
			String displayName = SIEMUtil.getAlertDisplayName(siemAlert.getAlertType());
			int index = SIEMUtil.getAlertTypeIndex(displayName);
			
			attrs.put(SIEMConstants.LEVEL, siemAlert.getLevel());
			attrs.put(SIEMConstants._SOURCE_APPLICATION, siemAlert.getSourceApplication());
			attrs.put(SIEMConstants._ALERT_TYPE, siemAlert.getAlertType());
			attrs.put(SIEMConstants._ALERT_TYPE_INDEX, index);
			
			if (siemAlert.getTargetGroupName() != null) {
				
				attrs.put(SIEMConstants._TARGET_GROUP_NAME, siemAlert.getTargetGroupName());
			}
			
			if (siemAlert.getTargetGroupType() != null) {
				
				attrs.put(SIEMConstants._TARGET_GROUP_NAME, siemAlert.getTargetGroupType());
			}
			
			if (index == 1 || index == 2 || index == 11) {
				
				attrs.put(SIEMConstants.ACTION, siemAlert.getAction());
				displayName += " " + siemAlert.getAction();
			}
			
			alert.setAttributes(attrs);
			alert.setDisplayName(displayName);
			
			Sequencer sequencer = new Sequencer();
			alert.setName(sequencer.generateId(context, alert));
			alert.setType(SIEMConstants.SIEM_ALERT);
			log.debug("About to create IdentityIQ Alert for : " + alert.toXml());
			
			context.saveObject(alert);
			context.commitTransaction();
			
			Alert check = context.getObjectByName(Alert.class, alert.getName());
			if (log.isDebugEnabled()) {
				
				log.debug("The check is : " + check.toXml());
			}
			
			if (null != check) {
				
				siemAlertService.updateAlertId(siemAlert.getId(), check.getId());
				count++;
			} else {
				
				log.error("No newly created Alert object was found, cannot update plugin table!");
			}
			
			context.decache(check);
		}
		
		log.trace("Exiting createAlerts, alerts created : " + count);
	}
	
	/**
	 * Function that will perform actions specified by the Alert
	 *
	 * @param context
	 *            The SailPointContext
	 * @throws GeneralException
	 */
	public void actionAlerts(SailPointContext context) throws GeneralException {
		
		log.trace("Entering actionAlerts...");
		
		int count = 0;
		List<SIEMAlertDTO> toAction = siemAlertService.getOpenAlerts(prioritizeByLevel);
		log.debug("Size of the toAction list is : " + toAction.size());
		
		for (SIEMAlertDTO siemAlert : toAction) {
			
			log.debug("The SIEM alert is : " + siemAlert.getId());
			log.debug("The alert type is : " + siemAlert.getAlertType());
			if (siemAlert.getAlertType().contains(SIEMConstants.IDENTITY_FOWARD_SLASH)) {
				
				log.debug("Identity based alert found : " + siemAlert.getAlertId());
				processIdentityAlert(context, siemAlert);
				count++;
			} else if (siemAlert.getAlertType().contains(SIEMConstants.APPLICATION_FOWARD_SLASH)) {
				
				log.debug("Application based alert found : " + siemAlert.getAlertId());
				processApplicationAlert(context, siemAlert);
				count++;
			} else {
				
				log.error("Unknown alert type detected for Alert object : " + siemAlert.getId());
			}
		}
		
		log.trace("Exiting actionAlerts, alerts actioned : " + count);
	}
	
	/**
	 * Function that will prune alerts if plugin setting is configured to do so
	 *
	 * @throws GeneralException
	 */
	public void pruneAlerts(SailPointContext context) throws GeneralException {
		
		log.trace("Entering pruneAlerts, purgeByDays is : " + purgeByDays);
		
		// Do not want to purge anything if plugin setting isn't a positive integer
		if (purgeByDays <= 0) {
			
			log.debug("No purgeByDays set in plugin, exiting pruneAlerts without deleting anything");
			return;
		}
		
		int count = 0;
		boolean success;
		
		// current time minus purgeByDays
		Date now = new Date();
		Calendar calc = Calendar.getInstance();
		calc.setTime(now);
		calc.add(Calendar.DATE, -purgeByDays);
		Date then = calc.getTime();
		
		List<SIEMAlertDTO> toPrune = siemAlertService.getOldAlerts(then.getTime(), prioritizeByLevel);
		for (SIEMAlertDTO siemAlert : toPrune) {
			
			if (null != siemAlert.getAlertId()) { // YP: Check for null otherwise the deleteAlertObject throws an error
				
				success = deleteAlertObject(context, siemAlert.getAlertId());
				if (success) {
					
					siemAlertService.deleteAlert(siemAlert.getId());
					count++;
				}
			}
		}
		
		log.trace("Exiting pruneALerts, alerts pruned: " + count);
	}
	
	/**
	 * Function to delete the SailPoint Alert object after elapsed days, if
	 * configured.
	 *
	 * @param context
	 * @param id
	 * @return true if delete succeeded
	 * @throws GeneralException
	 */
	public boolean deleteAlertObject(SailPointContext context, String id) throws GeneralException {
		
		log.trace("Entering deleteAlertObject with alert : " + id);
		
		boolean success = false;
		Alert alert = context.getObjectById(Alert.class, id);
		if (null != alert) {
			
			Terminator t1000 = new Terminator(context);
			try {
				
				t1000.deleteObject(alert);
				success = true;
			} catch (Exception e) {
				
				log.error("Error occurred pruning SIEM Alert object : " + id);
				e.printStackTrace();
			}
		}
		
		log.trace("Exiting deleteAlertObject for Alert : " + id + " and success is : " + success);
		return success;
	}
	
	/**
	 * Function to processes all Identity related alerts.
	 *
	 * @param context
	 * @param alert
	 * @throws GeneralException
	 */
	public void processIdentityAlert(SailPointContext context, SIEMAlertDTO alert) throws GeneralException {
		
		log.trace("Entering processIdentityAlert...");
		
		Alert iiqAlert = context.getObjectById(Alert.class, alert.getAlertId());
		if (null != iiqAlert) {
			
			Map<String, Object> args = new HashMap<>();
			
			String displayName = iiqAlert.getDisplayName();
			int index = (int) iiqAlert.getAttribute(SIEMConstants._ALERT_TYPE_INDEX);
			String identityId = iiqAlert.getTargetId();
			String nativeId = alert.getNativeId();
			String applicationName = alert.getSourceApplication();
			// TODO : check if we can use constants which are case insensitive
			String action = SIEMConstants.DISABLE;
			String result = SIEMConstants.SUCCESS;
			
			if (alert.getAction() != null && !alert.getAction().isEmpty()) {
				
				action = alert.getAction();
			}
			
			boolean isAll = false;
			log.debug("displayName : " + displayName);
			log.debug("identityId : " + identityId);
			log.debug("application name : " + applicationName);
			if (index == 8 || index == 9) {
				
				log.debug("SIEM certification request for Identity..." + identityId);
				args.put(SIEMConstants.IDENTITY_ID, identityId);
				args.put(SIEMConstants.APPLICATION_NAME, applicationName);
				// certificiations
				if (index == 9) {
					
					isAll = true;
				}
				
				args.put(SIEMConstants.IS_ALL, isAll);
				result = generateIdCertification(context, args, result, iiqAlert);
				
				Date closeDate = new Date();
				siemAlertService.updateAlertProcessed(alert.getId(), closeDate.getTime());
				closeAlert(context, iiqAlert.getId(), closeDate, result, SIEMConstants.CERTIFICATION);
			}
			// TODO do we want to fall back on this by default?
			else {
				
				log.debug("SIEM provisioning request for Identity..." + identityId);
				boolean isAccount = false;
				boolean isEntitlement = false;
				boolean isPassword = false;
				boolean isBulkEntitlement = false;
				boolean isOverride = alert.isOverride();
				
				args.put(SIEMConstants.IS_OVERRIDE, isOverride);
				
				if (index == 2 || index == 4 || index == 7) {
					
					log.debug("Bulk SIEM request found...setting isAll");
					isAll = true;
				}
				
				if (index == 1 || index == 2) {
					
					log.debug("Identity account action found, setting isAccount...");
					isAccount = true;
				}
				
				if (index == 3 || index == 4 || index == 5) {
					
					if (index == 5) {
						
						log.debug("Bulk entitlement SIEM request found, setting isBulkEntitlement...");
						isBulkEntitlement = true;
					} else {
						
						log.debug("Single entitlement SIEM request found, setting isEntitlement...");
						isEntitlement = true;
						args.put(SIEMConstants.TARGET_GROUP_NAME, alert.getTargetGroupName());
						args.put(SIEMConstants.TARGET_GROUP_TYPE, alert.getTargetGroupType());
					}
				}
				
				if (index == 6 || index == 7) {
					
					log.debug("Password SIEM request found, setting isPassword...");
					isPassword = true;
				}
				// standard provisioning case
				args.put(SIEMConstants.IDENTITY_ID, identityId);
				args.put(SIEMConstants.APPLICATION_NAME, applicationName);
				args.put(SIEMConstants.ACTION, action);
				args.put(SIEMConstants.IS_ALL, isAll);
				args.put(SIEMConstants.IS_ACCOUNT, isAccount);
				args.put(SIEMConstants.IS_ENTITLEMENT, isEntitlement);
				args.put(SIEMConstants.IS_BULK_ENTITLEMENT, isBulkEntitlement);
				args.put(SIEMConstants.IS_PASSWORD, isPassword);
				args.put(SIEMConstants.IS_OVERRIDE, isOverride);
				args.put(SIEMConstants.NATIVE_ID, nativeId);
				
				log.debug("SIEM Identity provisioning starting...");
				
				result = provisionIdentity(context, args, result, iiqAlert);
				log.debug("After provisioning, the result is : " + result);
				
				Date closeDate = new Date();
				siemAlertService.updateAlertProcessed(alert.getId(), closeDate.getTime());
				closeAlert(context, iiqAlert.getId(), closeDate, result, SIEMConstants.PROVISION);
			}
		}
		
		log.trace("Exiting processIdentityAlert...");
	}
	
	/**
	 * Function to processes all Application related alerts.
	 *
	 * @param context
	 * @param alert
	 * @throws GeneralException
	 */
	public void processApplicationAlert(SailPointContext context, SIEMAlertDTO alert) throws GeneralException {
		
		log.trace("Entering processApplicationAlert...");
		
		Alert iiqAlert = context.getObjectById(Alert.class, alert.getAlertId());
		if (null != iiqAlert) {
			
			String displayName = iiqAlert.getDisplayName();
			int index = (int) iiqAlert.getAttribute(SIEMConstants._ALERT_TYPE_INDEX);
			String action = alert.getAction();
			String result = SIEMConstants.SUCCESS;
			
			log.debug("displayname : " + displayName);
			HashMap<String, Object> args = new HashMap<>();
			args.put(SIEMConstants.TARGET_GROUP_NAME, alert.getTargetGroupName());
			args.put(SIEMConstants.TARGET_GROUP_TYPE, alert.getTargetGroupType());
			args.put(SIEMConstants.APPLICATION_NAME, alert.getSourceApplication());
			
			if (index == 12 || index == 13) {
				
				log.debug("found application certification alert...");
				
				boolean isGroupMembership = false;
				boolean isFullApplication = false;
				
				if (index == 12) {
					
					isGroupMembership = true;
				}
				
				if (index == 13) {
					
					isFullApplication = true;
				}
				
				args.put(SIEMConstants.IS_GROUP_MEMBERSHIP, isGroupMembership);
				args.put(SIEMConstants.IS_FULL_APPLICATION, isFullApplication);
				result = generateApplicationCertification(context, args, result, iiqAlert);
				Date closeDate = new Date();
				siemAlertService.updateAlertProcessed(alert.getId(), closeDate.getTime());
				closeAlert(context, iiqAlert.getId(), closeDate, result, SIEMConstants.CERTIFICATION);
				
			} else if (index == 10 || index == 11) {
				
				log.debug("found application provision alert...");
				boolean disableGroup = false;
				boolean disableAccounts = false;
				boolean isOverride = alert.isOverride();
				// args.put(SIEMConstants.IS_OVERRIDE, isOverride);
				
				if (index == 10) {
					
					disableGroup = true;
				}
				
				if (index == 11) {
					
					disableAccounts = true;
				}
				
				args.put(SIEMConstants.DISABLE_GROUP, disableGroup);
				args.put(SIEMConstants.DISABLE_ACCOUNTS, disableAccounts);
				args.put(SIEMConstants.IS_OVERRIDE, isOverride);
				args.put(SIEMConstants.ACTION, action);
				
				result = provisionApplication(context, args, result, iiqAlert);
				Date closeDate = new Date();
				siemAlertService.updateAlertProcessed(alert.getId(), closeDate.getTime());
				closeAlert(context, iiqAlert.getId(), closeDate, result, SIEMConstants.PROVISION);
			} else {
				
				Date closeDate = new Date();
				log.error("Unknown Alert type found for SIEM Application! IIQ Alert ID : " + iiqAlert.getId());
				result = "Fail! Unknown Alert type found for SIEM Application";
				closeAlert(context, iiqAlert.getId(), closeDate, result, SIEMConstants.NONE);
			}
		}
		
		log.trace("Exiting processApplicationAlert...");
	}
	
	/**
	 * Function to find an Identity in IdentityIQ based on link with nativeID and
	 * application provided.
	 *
	 * @param context
	 * @param alert
	 * @return
	 * @throws GeneralException
	 */
	public String findMatchingIdentityId(SailPointContext context, SIEMAlertDTO alert) throws GeneralException {
		
		log.trace("Entering findMatchingIdentity...");
		
		String nativeId = alert.getNativeId();
		String sourceApp = alert.getSourceApplication();
		String id = null;
		
		QueryOptions queryOptions = new QueryOptions();
		Filter filterNativeIdentity = Filter.eq(SIEMConstants.FILTER_NATIVE_IDENTITY, nativeId);
		Filter filterApplicationName = Filter.eq(SIEMConstants.FILTER_APPLICATION_NAME, sourceApp);
		
		queryOptions.addFilter(filterNativeIdentity);
		queryOptions.addFilter(filterApplicationName);
		
		List<String> props = new ArrayList<>();
		props.add(SIEMConstants.IDENTITY_DOT_ID);
		
		int count = context.countObjects(Link.class, queryOptions);
		if (count > 1) {
			
			// TODO may be able to handle this error better?
			log.error(
					"Multiple identities match a single application/native identity - aborting SIEM alert operation : "
							+ alert.getId());
			return null;
		}
		
		if (count == 0) {
			
			log.error("No accounts matching nativeIdentity in SIEM alert - aborting SIEM alert operation : "
					+ alert.getId());
		}
		
		Iterator<Object[]> it = context.search(Link.class, queryOptions, props);
		if (null != it) {
			
			try {
				
				while (it.hasNext()) {
					
					Object[] row = (Object[]) it.next();
					id = (String) row[0];
				}
				
			} catch (Exception e) {
				
				log.error("Error iterating identity results in findMatchingIdentityId : " + e.toString());
			} finally {
				
				Util.flushIterator(it);
			}
		}
		
		log.trace("Exiting findMatchingIdentity...");
		return id;
	}
	
	/**
	 * Function to provision, or launch provisioning workflow for the SIEM alert.
	 *
	 * @param context
	 *            SailPointContext for use with provisioning
	 * @param args
	 *            Argument map to determine provisioning logic
	 * @param iiqAlert
	 * @return Success if no obvious errors encountered
	 * @throws GeneralException
	 */
	@SuppressWarnings("unchecked")
	public String provisionIdentity(SailPointContext context, Map<String, Object> args, String result, Alert iiqAlert)
			throws GeneralException {
		
		log.trace("Entering provisionIdentity...");
		
		String identityId = (String) args.get(SIEMConstants.IDENTITY_ID);
		String nativeId = (String) args.get(SIEMConstants.NATIVE_ID);
		String applicationName = (String) args.get(SIEMConstants.APPLICATION_NAME);
		String action = (String) args.get(SIEMConstants.ACTION);
		boolean isOverride = (boolean) args.get(SIEMConstants.IS_OVERRIDE);
		boolean isAll = (boolean) args.get(SIEMConstants.IS_ALL);
		boolean isAccount = (boolean) args.get(SIEMConstants.IS_ACCOUNT);
		boolean isEntitlement = (boolean) args.get(SIEMConstants.IS_ENTITLEMENT);
		boolean isBulkEntitlement = (boolean) args.get(SIEMConstants.IS_BULK_ENTITLEMENT);
		boolean isPassword = (boolean) args.get(SIEMConstants.IS_PASSWORD);
		
		log.debug("The provisioning operation for : " + identityId + " is " + action);
		log.debug("The override value is : " + isOverride);
		
		Provisioner provisioner = new Provisioner(context);
		ProvisioningPlan plan = new ProvisioningPlan();
		ProvisioningPlan.AccountRequest acctReq = null;
		Identity identity = context.getObjectById(Identity.class, identityId);
		if (null == identity) {
			
			log.error("No Identity found for SIEM Alert provisioning! Aborting..." + identityId);
			result = "Fail! No identity found for SIEM Alert: " + identityId;
			return result;
		}
		
		if (!action.equalsIgnoreCase(SIEMConstants.DISABLE) && !action.equalsIgnoreCase(SIEMConstants.DELETE)) {
			
			log.error("Unknown operation in SIEM Identity Provisioning : " + action + "... Aborting!" + identityId);
			result = "Fail! Unknown operation: " + action;
			return result;
		}
		plan.setIdentity(identity);
		
		if (isAccount) {
			
			if (isAll) {
				
				log.debug("Have a bulk SIEM account request");
				List<Link> links = identity.getLinks();
				for (Link link : links) {
					
					log.debug("Application name : " + link.getApplicationName());
					if (!link.getApplication().isAuthoritative()) {
						
						log.debug("It is not authoritative application.");
						log.debug("Native identity id : " + link.getNativeIdentity());
						
						if (action.equalsIgnoreCase(SIEMConstants.DISABLE)) {
							
							acctReq = new ProvisioningPlan.AccountRequest(
									ProvisioningPlan.AccountRequest.Operation.Disable, link.getApplicationName(), null,
									link.getNativeIdentity());
						}
						
						if (action.equalsIgnoreCase(SIEMConstants.DELETE)) {
							acctReq = new ProvisioningPlan.AccountRequest(
									ProvisioningPlan.AccountRequest.Operation.Delete, link.getApplicationName(), null,
									link.getNativeIdentity());
						}
						
						plan.add(acctReq);
					} else {
						
						log.debug("Authoritative link found, ignoring...");
					}
				}
				
				log.debug("The plan is : " + plan.toXml());
			} else {
				
				log.debug("Have a SIEM account request");
				Application app = context.getObjectByName(Application.class, applicationName);
				log.debug("nativeId : " + nativeId);
				if (null != app) {
					
					if (!app.isAuthoritative()) {
						
						if (action.equalsIgnoreCase(SIEMConstants.DISABLE)) {
							
							acctReq = new ProvisioningPlan.AccountRequest(
									ProvisioningPlan.AccountRequest.Operation.Disable, applicationName, null, nativeId);
						}
						
						if (action.equalsIgnoreCase(SIEMConstants.DELETE)) {
							
							acctReq = new ProvisioningPlan.AccountRequest(
									ProvisioningPlan.AccountRequest.Operation.Delete, applicationName, null, nativeId);
						}
						
						plan.add(acctReq);
						log.debug("The plan is: " + plan.toXml());
					} else {
						
						log.error("Cannot perform operation on authoritative application!");
						result = "Fail! Cannot perform delete/disable on authoritative application";
						return result;
					}
				}
				
			}
		} else if (isEntitlement) {
			
			if (isAll) {
				
				log.debug("Have a SIEM entitlements request (for all on single account)");
				Application app = context.getObjectByName(Application.class, applicationName);
				
				if (null != app) {
					
					IdentityService identityService = new IdentityService(context);
					Link link = identityService.getLink(identity, app, null, nativeId);
					
					if (null != link) {
						
						acctReq = new ProvisioningPlan.AccountRequest(ProvisioningPlan.AccountRequest.Operation.Modify,
								applicationName, null, nativeId);
						Schema schema = app.getAccountSchema();
						List<String> attrs = null;
						
						if (null != schema) {
							
							attrs = schema.getEntitlementAttributeNames();
							if (null != attrs) {
								
								for (String attr : attrs) {
									
									if (attr == null) {
										
										continue;
									}
									
									Object val = link.getAttribute(attr);
									if (null != val) {
										
										List<Object> vals = Util.asList(val);
										for (Object obj : vals) {
											
											if (null != obj) {
												
												String strVal = obj.toString();
												ProvisioningPlan.AttributeRequest attReq = new ProvisioningPlan.AttributeRequest();
												attReq.setOperation(ProvisioningPlan.Operation.Remove);
												attReq.setValue(strVal);
												attReq.setName(attr);
												acctReq.add(attReq);
											}
										}
									}
								}
							}
						}
						
						plan.add(acctReq);
						log.debug("The plan is : " + plan.toXml());
					}
				}
			} else {
				
				log.debug("Have a SIEM entitlement request");
				
				acctReq = new ProvisioningPlan.AccountRequest(ProvisioningPlan.AccountRequest.Operation.Modify,
						applicationName, null, nativeId);
				ProvisioningPlan.AttributeRequest attReq = new ProvisioningPlan.AttributeRequest();
				String targetGroupName = (String) args.get(SIEMConstants.TARGET_GROUP_NAME);
				String targetGroupType = (String) args.get(SIEMConstants.TARGET_GROUP_TYPE);
				attReq.setName(targetGroupType);
				attReq.setOperation(ProvisioningPlan.Operation.Remove);
				attReq.setValue(targetGroupName);
				acctReq.add(attReq);
				plan.add(acctReq);
				
				log.debug("The plan is : " + plan.toXml());
			}
		} else if (isBulkEntitlement) {
			
			log.debug("Have a bulk SIEM entitlement request");
			
			List<Link> links = identity.getLinks();
			for (Link link : links) {
				
				if (null != link) {
					
					acctReq = new ProvisioningPlan.AccountRequest(ProvisioningPlan.AccountRequest.Operation.Modify,
							link.getApplicationName(), null, link.getNativeIdentity());
					Application app = link.getApplication();
					Schema schema = app.getAccountSchema();
					List<String> attrs = null;
					
					if (null != schema) {
						
						attrs = schema.getEntitlementAttributeNames();
						if (null != attrs) {
							
							for (String attr : attrs) {
								
								if (attr == null) {
									
									continue;
								}
								
								Object val = link.getAttribute(attr);
								if (val != null) {
									List<Object> vals = Util.asList(val);
									for (Object obj : vals) {
										if (null != obj) {
											String strVal = obj.toString();
											ProvisioningPlan.AttributeRequest attReq = new ProvisioningPlan.AttributeRequest();
											attReq.setOperation(ProvisioningPlan.Operation.Remove);
											attReq.setValue(strVal);
											attReq.setName(attr);
											acctReq.add(attReq);
										}
									}
								}
							}
						}
					}
					
					plan.add(acctReq);
				}
			}
			
			log.debug("The plan is : " + plan.toXml());
		} else if (isPassword) {
			
			// TODO for now we are just provisioning Active Directory account password
			// resets - this isn't great
			if (!deferProvisioning && !isOverride) {
				
				if (isAll) {
					
					// go through all app links and see
					log.debug("Have a bulk SIEM password request");
					List<Link> links = identity.getLinks();
					for (Link link : links) {
						
						if (null != link) {
							
							Application app = link.getApplication();
							if (app.getType().equalsIgnoreCase(SIEMConstants.ACTIVE_DIRECTORY_DIRECT)) {
								
								acctReq = new ProvisioningPlan.AccountRequest(
										ProvisioningPlan.AccountRequest.Operation.Modify, link.getApplicationName(),
										null, link.getNativeIdentity());
								ProvisioningPlan.AttributeRequest attReq = new ProvisioningPlan.AttributeRequest();
								attReq.setOperation(ProvisioningPlan.Operation.Set);
								attReq.setName(SIEMConstants.PWD_LAST_SET);
								attReq.setValue(true);
								acctReq.add(attReq);
							} else {
								
								log.debug("Skipping application password reset for : " + app.getName()
										+ " unsupported type : " + app.getType());
								if (result.equalsIgnoreCase("success")) {
									
									result = "Fail! Skipping application password reset for : " + app.getName()
											+ " unsupported type : " + app.getType();
								} else {
									
									result = result + "Fail! Skipping application password reset for : " + app.getName()
											+ " unsupported type : " + app.getType();
								}
								
								continue;
							}
							
							plan.add(acctReq);
						}
					}
					
					log.debug("The plan is : " + plan.toXml());
				} else {
					
					Application app = context.getObjectByName(Application.class, applicationName);
					if (null != app) {
						
						if (app.getType().equalsIgnoreCase(SIEMConstants.ACTIVE_DIRECTORY_DIRECT)) {
							
							acctReq = new ProvisioningPlan.AccountRequest(
									ProvisioningPlan.AccountRequest.Operation.Modify, applicationName, null, nativeId);
							ProvisioningPlan.AttributeRequest attReq = new ProvisioningPlan.AttributeRequest();
							attReq.setOperation(ProvisioningPlan.Operation.Set);
							attReq.setName(SIEMConstants.PWD_LAST_SET);
							attReq.setValue(true);
							acctReq.add(attReq);
							plan.add(acctReq);
						} else {
							
							log.error("SIEM Password reset not available for application : " + applicationName
									+ " of type: " + app.getType());
							result = "Fail! SIEM Password reset not available for application : " + applicationName;
							return result;
						}
					}
				}
			} else {
				
				log.debug("Password provisioning deferred, don't both with creating plans, projects etc...");
			}
		} else {
			
			log.debug("Nothing TODO.");
		}
		// compile the plan into project
		
		ProvisioningProject provisioningProject = provisioner.compile(plan);
		log.debug("The provisioning project is: " + provisioningProject.toXml());
		if (deferProvisioning || isOverride) {
			
			log.debug("SIEM provisioning deferred to workflow...launching...");
			if (log.isDebugEnabled()) {
				
				log.debug("... with project : " + provisioningProject.toXml());
			}
			
			try {
				
				Workflower workflower = new Workflower(context);
				
				Attributes<String, Object> vars = new Attributes<>();
				
				vars.put(SIEMConstants.PLAN, plan);
				vars.put(SIEMConstants.PROJECT, provisioningProject);
				vars.put(SIEMConstants.IS_PASSWORD, isPassword);
				vars.put(SIEMConstants.IS_ALL, isAll);
				
				// Workflow workflow = context.getObjectByName(Workflow.class,
				// provisioningWorkflow);
				WorkflowLaunch workflowLaunch = new WorkflowLaunch();
				// workflowLaunch.setTarget();
				workflowLaunch.setWorkflowRef(provisioningWorkflow);
				workflowLaunch.setCaseName(provisioningWorkflow + " - " + identityId);
				workflowLaunch.setLauncher(SIEMConstants.SIEM_SERVICE);
				workflowLaunch.setVariables(vars);
				workflowLaunch = workflower.launch(workflowLaunch);
				
			} catch (Exception e) {
				
				result = "Fail! Error launching provisioning workflow.";
			}
			
		} else {
			
			log.debug("SIEM Direct provisioning selected, firing plan!");
			if (log.isDebugEnabled()) {
				
				log.debug("... with project: " + provisioningProject.toXml());
			}
			
			try {
				
				provisioner.execute(provisioningProject);
			} catch (Exception e) {
				
				log.error("Error in SIEM Identity provisioning... " + e.toString());
				result = "Fail! Error executing provisioning plan";
			}
		}
		
		log.debug("Exiting identity provision..." + result);
		if (Auditor.isEnabled(SIEMConstants.SIEM_PROVISIONING)) {
			
			log.debug("Auditing SIEM identity provisioning");
			auditProvisioning(result, iiqAlert, applicationName, nativeId, action);
		}
		
		log.trace("Exiting provisionIdentity...");
		return result;
	}
	
	/**
	 * Function to provision an application.
	 * 
	 * @param context
	 *            The SailPointContext.
	 * @param args
	 *            Map of arguments for the application provisioning.
	 * @param result
	 *            stores the result, defaults to success.
	 * @param iiqAlert
	 * @return Success if no obvious errors encountered.
	 * @throws GeneralException
	 */
	public String provisionApplication(SailPointContext context, Map<String, Object> args, String result,
			Alert iiqAlert) throws GeneralException {
		
		log.trace("Entering provisionApplication...");
		
		// TODO these are likely heavy tasks, so might benefit from seperate thread of
		// execution
		boolean disableGroup = (boolean) args.get(SIEMConstants.DISABLE_GROUP);
		boolean disableAccounts = (boolean) args.get(SIEMConstants.DISABLE_ACCOUNTS);
		boolean isOverride = (boolean) args.get(SIEMConstants.IS_OVERRIDE);
		
		String applicationName = (String) args.get(SIEMConstants.APPLICATION_NAME);
		String action = (String) args.get(SIEMConstants.ACTION);
		List<ProvisioningProject> projects = new ArrayList<>();
		Application app = context.getObjectByName(Application.class, applicationName);
		
		if (app == null) {
			
			log.error("Application not found in SIEM Application alert : " + applicationName);
			result = "Fail! No application found : " + applicationName;
			return result;
		}
		
		Provisioner provisioner = new Provisioner(context);
		
		if (disableGroup) {
			
			log.debug("SIEM Application Alert to disable group.");
			
			// list to whole all projects
			String targetGroupName = (String) args.get(SIEMConstants.TARGET_GROUP_NAME);
			String targetGroupType = (String) args.get(SIEMConstants.TARGET_GROUP_TYPE);
			// make group non-requestable
			
			ManagedAttribute managedAttribute = ManagedAttributer.get(context, app, targetGroupType, targetGroupName);
			if (managedAttribute == null) {
				
				log.error("ManagedAttribute specified in SIEM Application disable group not found! Name: "
						+ targetGroupName + " type : " + targetGroupType + " app : " + applicationName);
				result = "Fail! ManagedAttribute not found : " + applicationName + ", " + targetGroupType + ", "
						+ targetGroupName;
				return result;
			}
			
			QueryOptions queryOptions = new QueryOptions();
			Filter filter = Filter.and(Filter.eq(SIEMConstants.FILTER_APPLICATION, app),
					Filter.ignoreCase(Filter.eq(SIEMConstants.FILTER_NAME, targetGroupType)),
					Filter.eq(SIEMConstants.FILTER_AGGREGATION_STATE, IdentityEntitlement.AggregationState.Connected),
					Filter.ignoreCase(Filter.eq(SIEMConstants.FILTER_VALUE, targetGroupName)));
			List<String> props = new ArrayList<>();
			queryOptions.addFilter(filter);
			props.add(SIEMConstants.INSTANCE);
			props.add(SIEMConstants.NATIVE_IDENTITY);
			props.add(SIEMConstants.IDENTITY_DOT_NAME);
			
			Iterator<Object[]> it = context.search(IdentityEntitlement.class, queryOptions, props);
			if (null != it) {
				
				try {
					
					while (it.hasNext()) {
						
						Object[] row = it.next();
						
						String instance = (String) row[0];
						String nativeId = (String) row[1];
						String identityName = (String) row[2];
						
						Identity identity = context.getObjectByName(Identity.class, identityName);
						ProvisioningPlan plan = new ProvisioningPlan();
						plan.setIdentity(identity);
						ProvisioningPlan.AccountRequest acctReq = new ProvisioningPlan.AccountRequest(
								ProvisioningPlan.AccountRequest.Operation.Modify, applicationName, instance, nativeId);
						ProvisioningPlan.AttributeRequest attReq = new ProvisioningPlan.AttributeRequest();
						attReq.setName(targetGroupType);
						attReq.setOperation(ProvisioningPlan.Operation.Remove);
						attReq.setValue(targetGroupName);
						acctReq.add(attReq);
						plan.add(acctReq);
						
						ProvisioningProject proj = provisioner.compile(plan);
						projects.add(proj);
					}
				} catch (Exception e) {
					
					log.error("Error processing SEIM application bulk disable entitlement!");
					result = "Fail! Error processing SIEM application bulk disable entitlement";
				} finally {
					
					Util.flushIterator(it);
				}
			}
			// set the attribute as non-requestable
			if (managedAttribute.isRequestable()) {
				
				managedAttribute.setRequestable(false);
				context.saveObject(managedAttribute);
				context.commitTransaction();
			}
		} else if (disableAccounts) {
			
			log.debug("SIEM Application alert to disable accounts");
			
			QueryOptions queryOptions = new QueryOptions();
			Filter filterApplicationName = Filter.eq(SIEMConstants.FILTER_APPLICATION_NAME, applicationName);
			
			queryOptions.addFilter(filterApplicationName);
			
			List<String> props = new ArrayList<>();
			props.add(SIEMConstants.IDENTITY_DOT_NAME);
			props.add(SIEMConstants.NATIVE_IDENTITY);
			
			Iterator<Object[]> it = context.search(Link.class, queryOptions, props);
			if (null != it) {
				
				try {
					
					while (it.hasNext()) {
						
						Object[] row = it.next();
						String identityName = (String) row[0];
						String nativeId = (String) row[1];
						
						ProvisioningPlan plan = new ProvisioningPlan();
						Identity identity = context.getObjectByName(Identity.class, identityName);
						if (identity != null) {
							
							plan.setIdentity(identity);
							ProvisioningPlan.AccountRequest acctReq = null;
							if (action.equalsIgnoreCase(SIEMConstants.DISABLE)) {
								
								acctReq = new ProvisioningPlan.AccountRequest(
										ProvisioningPlan.AccountRequest.Operation.Disable, applicationName, null,
										nativeId);
								plan.add(acctReq);
							} else if (action.equalsIgnoreCase(SIEMConstants.DELETE)) {
								
								acctReq = new ProvisioningPlan.AccountRequest(
										ProvisioningPlan.AccountRequest.Operation.Delete, applicationName, null,
										nativeId);
								plan.add(acctReq);
							}
							
							ProvisioningProject proj = provisioner.compile(plan);
							projects.add(proj);
						} else {
							
							log.error("No matching identity found!");
							result = "Fail! No matching identity found";
						}
					}
				} catch (Exception e) {
					
					log.error("Error processing SIEM application bulk disable accounts!");
					result = "Fail! Error processing SIEM application bulk disable";
				} finally {
					
					Util.flushIterator(it);
				}
			}
		} else {
			
			log.error("Unknown SIEM application provisioning action!");
			result = "Fail! Unknown SIEM application provisioning action.";
		}
		
		log.debug("There are : " + projects.size() + " number of projects to provision");
		for (ProvisioningProject project : projects) {
			
			if (deferProvisioning || isOverride) {
				
				log.debug("SIEM Application provisioning deferred to workflow...launching...");
				if (log.isDebugEnabled()) {
					
					log.debug("...with the project : " + project.toXml());
				}
				
				try {
					
					Workflower wflower = new Workflower(context);
					
					Attributes<String, Object> vars = new Attributes<>();
					vars.put(SIEMConstants.PLAN, project.getMasterPlan());
					vars.put(SIEMConstants.PROJECT, project);
					
					// Workflow workflow = context.getObjectByName(Workflow.class,
					// provisioningWorkflow);
					WorkflowLaunch workflowLaunch = new WorkflowLaunch();
					// workflowLaunch.setTarget();
					workflowLaunch.setWorkflowRef(provisioningWorkflow);
					workflowLaunch.setCaseName(provisioningWorkflow + " - " + applicationName);
					workflowLaunch.setLauncher(SIEMConstants.SIEM_SERVICE);
					workflowLaunch.setVariables(vars);
					
					workflowLaunch = wflower.launch(workflowLaunch);
					
				} catch (Exception e) {
					
					if (result.startsWith("Success")) {
						
						result = "Error launching SIEM application provisioning for : " + project.getIdentity();
					} else {
						
						result += " Error launching SIEM application provisioning for : " + project.getIdentity();
					}
				}
			} else {
				
				log.debug("SIEM Application Direct provisioning selected, firing plan...");
				if (log.isDebugEnabled()) {
					
					log.debug("...with the project: " + project.toXml());
				}
				
				try {
					
					provisioner.execute(project);
				} catch (Exception e) {
					
					if (result.startsWith("Success")) {
						
						result = "Error launching SIEM application provisioning for : " + project.getIdentity();
					} else {
						
						result += " Error launching SIEM application provisioning for : " + project.getIdentity();
					}
				}
			}
			
			if (Auditor.isEnabled(SIEMConstants.SIEM_PROVISIONING)) {
				
				log.debug("Auditing SIEM application provisioning...");
				auditProvisioning(result, iiqAlert, applicationName, project.getMasterPlan().getNativeIdentity(),
						action);
			}
		}
		
		log.trace("Exiting provisionApplication..." + result);
		return result;
	}
	
	/**
	 * Function to generate Identity based certifications.
	 * 
	 * @param context
	 *            The SailPointContext.
	 * @param args
	 *            map of the arguments that will define which certification to
	 *            launch.
	 * @param result
	 *            The result of the certification generation, defaults to success.
	 * @param iiqAlert
	 */
	public String generateIdCertification(SailPointContext context, Map<String, Object> args, String result,
			Alert iiqAlert) throws GeneralException {
		
		log.trace("Entering generateCertifications...");
		
		String identityId = (String) args.get(SIEMConstants.IDENTITY_ID);
		String applicationName = (String) args.get(SIEMConstants.APPLICATION_NAME);
		
		boolean isAll = (boolean) args.get(SIEMConstants.IS_ALL);
		List<String> toCertify = new ArrayList<>();
		
		Identity id = context.getObjectById(Identity.class, identityId);
		if (null != id) {
			
			Identity manager = id.getManager();
			if (null == manager) {
				
				log.error("SIEM Alert Identity Certification failure - no manager! " + id.getName());
				result = "Failed! No manager found.";
				return result;
			}
			
			// Generate the cert
			List<String> apps = new ArrayList<>();
			
			toCertify.add(identityId);
			Identity requester = context.getObjectByName(Identity.class, SIEMConstants.SIEM_SERVICE);
			CertificationScheduler scheduler = new CertificationScheduler(context);
			CertificationSchedule schedule = scheduler.initializeScheduleBean(requester, Certification.Type.Identity);
			schedule.setRunNow(true);
			
			String siemCertName = "SIEM Identity Certification for " + id.getName() + " - " + id.getDisplayableName();
			CertificationDefinition template = context.getObject(CertificationDefinition.class,
					SIEMConstants.SIEM_IDENTITY_CERTIFICATION);
			CertificationDefinition siemCert = (CertificationDefinition) XMLObjectFactory.getInstance()
					.cloneWithoutId(template, (XMLReferenceResolver) context);
			try {
				
				siemCert.setIdentitiesToCertify(toCertify);
				siemCert.setCertifierSelectionType(CertificationDefinition.CertifierSelectionType.Manual);
				siemCert.setCertifierName(manager.getName());
				siemCert.setCertificationOwner(requester);
				siemCert.setShortNameTemplate(SIEMConstants.SIEM_IDENTITY_CERT);
				
				if (isAll) {
					
					siemCert.setName(siemCertName + " - All Accounts [" + new Date().toString() + "]");
				} else {
					
					siemCert.setName(siemCertName + " [" + new Date().toString() + "]");
					
					String appId = "";
					QueryOptions queryOptions = new QueryOptions();
					Filter filterName = Filter.eq(SIEMConstants.FILTER_NAME, applicationName);
					List<String> props = new ArrayList<>();
					props.add(SIEMConstants.ID);
					
					queryOptions.addFilter(filterName);
					Iterator<Object[]> it = context.search(Application.class, queryOptions, props);
					if (null != it) {
						
						try {
							
							while (it.hasNext()) {
								
								Object[] row = (Object[]) it.next();
								appId = (String) row[0];
								apps.add(appId);
							}
							siemCert.setIncludedApplicationIds(apps);
						} catch (Exception e) {
							
							log.error("Error iterating applications in generate ID certification " + e.toString());
							result = "Failed!" + e.toString();
						} finally {
							
							Util.flushIterator(it);
						}
					}
				}
				schedule.setDefinition(siemCert);
				// TaskSchedule taskSchedule = scheduler.saveSchedule(schedule, false);
			} catch (Exception e) {
				
				log.error("Error launching SIEM identity certification " + e.toString());
				result = "Failed! " + e.toString();
			}
		} else {
			
			log.error("SIEM Alert Identity Certification failure - no Identity! " + identityId);
			result = "Failed! No Identity found for : " + identityId;
		}
		
		log.trace("Exiting generateCertifications..." + result);
		return result;
	}
	
	/**
	 * Function for generating all application based certifications.
	 *
	 * @param context
	 * @param args
	 * @param iiqAlert
	 * @throws GeneralException
	 */
	public String generateApplicationCertification(SailPointContext context, Map<String, Object> args, String result,
			Alert iiqAlert) throws GeneralException {
		
		log.trace("Entering generateApplicationCertification...");
		
		String applicationName = (String) args.get("applicationName");
		Application app = context.getObjectByName(Application.class, applicationName);
		
		if (app == null) {
			
			log.error("Error generating SIEM application certification - No application found ");
			result = "Fail! No matching application found : " + applicationName;
			return result;
		}
		
		String appId = app.getId();
		if ((boolean) args.get(SIEMConstants.IS_GROUP_MEMBERSHIP)) {
			
			String targetGroupName = (String) args.get(SIEMConstants.TARGET_GROUP_NAME);
			String targetGroupType = (String) args.get(SIEMConstants.TARGET_GROUP_TYPE);
			log.debug("SIEM group membership certification requested for : " + targetGroupName + " on application : "
					+ app.getName());
			
			List<String> toCertify = new ArrayList<>();
			toCertify.add(appId);
			
			Identity requester = context.getObjectByName(Identity.class, SIEMConstants.SIEM_SERVICE);
			
			CertificationScheduler scheduler = new CertificationScheduler(context);
			CertificationSchedule schedule = scheduler.initializeScheduleBean(requester,
					Certification.Type.ApplicationOwner);
			schedule.setRunNow(true);
			String managedAttributeId = null;
			ManagedAttribute managedAttribute = ManagedAttributer.get(context, app, targetGroupType, targetGroupName);
			if (null == managedAttribute) {
				
				log.error("Managed attribute not found in SIEM Group Certification generation!" + targetGroupName);
				result = "Fail! Specific managed attribute not found : " + applicationName + ", " + targetGroupType
						+ ", " + targetGroupName;
				return result;
			}
			
			managedAttributeId = managedAttribute.getId();
			
			String siemCertName = "SIEM Group Certification for : " + targetGroupName;
			String clonedRuleName = null;
			CertificationDefinition template = context.getObject(CertificationDefinition.class,
					SIEMConstants.SIEM_ENTITLEMENT_OWNER_CERTIFICATION);
			CertificationDefinition siemCert = (CertificationDefinition) XMLObjectFactory.getInstance()
					.cloneWithoutId(template, (XMLReferenceResolver) context);
			
			try {
				
				siemCert.setName(siemCertName + " [" + new Date().toString() + "]");
				siemCert.setApplicationIds(toCertify);
				siemCert.setShortNameTemplate(SIEMConstants.SIEM_GROUP_CERT);
				siemCert.setCertifierSelectionType(CertificationDefinition.CertifierSelectionType.Manual);
				siemCert.setCertifierName(app.getOwner().getName());
				siemCert.setCertificationOwner(requester);
				String exclusionRuleName = template.getExclusionRuleName();
				if (null != exclusionRuleName && !exclusionRuleName.isEmpty()) {
					
					clonedRuleName = modifyExclusionRule(context, exclusionRuleName, managedAttributeId);
					siemCert.setExclusionRuleName(clonedRuleName);
					
				}
				
				schedule.setDefinition(siemCert);
				// TaskSchedule taskSchedule = scheduler.saveSchedule(schedule, false);
				if (null != clonedRuleName && !clonedRuleName.isEmpty()) {
					
					removeModifiedExclusionRule(context, clonedRuleName);
				}
			} catch (Exception e) {
				
				log.error("Error launching SIEM Application certification " + e.toString());
				result = "Fail! Error launching certification";
			}
			
		} else if ((boolean) args.get("isFullApplication")) {
			
			// full application cert
			log.debug("SIEM Application Owner certification requested for : " + app.getName());
			Identity requester = context.getObjectByName(Identity.class, SIEMConstants.SIEM_SERVICE);
			List<String> toCertify = new ArrayList<>();
			toCertify.add(appId);
			
			CertificationScheduler scheduler = new CertificationScheduler(context);
			CertificationSchedule schedule = scheduler.initializeScheduleBean(requester,
					Certification.Type.ApplicationOwner);
			schedule.setRunNow(true);
			
			String siemCertName = "SIEM Application Certification for : " + applicationName;
			
			CertificationDefinition template = context.getObject(CertificationDefinition.class,
					SIEMConstants.SIEM_APPLICATION_OWNER_CERTIFICATION);
			CertificationDefinition siemCert = (CertificationDefinition) XMLObjectFactory.getInstance()
					.cloneWithoutId(template, (XMLReferenceResolver) context);
			
			try {
				
				siemCert.setName(siemCertName + " [" + new Date().toString() + "]");
				siemCert.setApplicationIds(toCertify);
				siemCert.setShortNameTemplate(SIEMConstants.SIEM_APPLICATION_CERT);
				siemCert.setCertifierSelectionType(CertificationDefinition.CertifierSelectionType.Manual);
				siemCert.setCertifierName(app.getOwner().getName());
				siemCert.setCertificationOwner(requester);
				
				schedule.setDefinition(siemCert);
				// TaskSchedule taskSchedule = scheduler.saveSchedule(schedule, false);
			} catch (Exception e) {
				
				log.error("Error launching SIEM Application certification " + e.toString());
				result = "Fail! Error launching certification!";
			}
		} else {
			
			// unknown cert type
			log.error("Unknown certification type passed to SIEM Application certification!");
			result = "Fail! Unknown certification type";
		}
		
		log.trace("Exiting generateApplicationCertification..." + result);
		return result;
	}
	
	/**
	 * Function to dynamically modify the certification exclusion rule to specify a
	 * single group/ma.
	 *
	 * @param context
	 *            The SailPointContext.
	 * @param ruleName
	 *            Exclusion rule to modify.
	 * @param maId
	 *            Hibernate ID of the managed attribute to include in the
	 *            certification.
	 * @return
	 */
	public String modifyExclusionRule(SailPointContext context, String ruleName, String maId) throws GeneralException {
		
		log.trace("Entering modifyExclusionRule...");
		
		// TODO
		String clonedRuleName = "";
		
		Rule clonedRule = null;
		Rule exclusionRule = context.getObjectByName(Rule.class, ruleName);
		
		if (null != exclusionRule) {
			
			clonedRule = (Rule) exclusionRule.derive(context);
			ManagedAttribute managedAttr = context.getObjectById(ManagedAttribute.class, maId);
			String script = clonedRule.getSource();
			script = script.replace(SIEMConstants.SCRIPT_GROUP_VALUE, managedAttr.getValue());
			script = script.replace(SIEMConstants.SCRIPT_GROUP_TYPE, managedAttr.getAttribute());
			script = script.replace(SIEMConstants.SCRIPT_GROUP_APPLICATION_ID, managedAttr.getApplicationId());
			clonedRule.setSource(script);
			double rand = Math.random() * 1000;
			clonedRuleName = ruleName + " " + rand;
			clonedRule.setName(clonedRuleName);
			context.saveObject(clonedRule);
			context.commitTransaction();
		}
		
		log.trace("Exiting modifyExclusionRule...");
		return clonedRuleName;
	}
	
	/**
	 * Function/rule to remove customized exclusion rule attached to group owner
	 * certification. Launches workflow to do this, as trying to delete the rule
	 * before the certification has finished generating can be problematic.
	 *
	 * @param context
	 *            The SailPointContext.
	 * @param modifiedName
	 *            Name of the custom rule to remove.
	 * @throws GeneralException
	 */
	public void removeModifiedExclusionRule(SailPointContext context, String modifiedName) throws GeneralException {
		
		log.trace("Entering removeModifiedExclusionRule...");
		
		try {
			
			HashMap<String, Object> launchArgsMap = new HashMap<>();
			launchArgsMap.put(SIEMConstants.RULE_NAME, modifiedName);
			long launchTime = System.currentTimeMillis() + 10000;
			String caseName = SIEMConstants.SIEM_REMOVE_EXCLUSION_RULE + ": " + modifiedName;
			Attributes<String, Object> reqArgs = new Attributes<>();
			reqArgs.put(StandardWorkflowHandler.ARG_REQUEST_DEFINITION,
					sailpoint.request.WorkflowRequestExecutor.DEFINITION_NAME);
			reqArgs.put(StandardWorkflowHandler.ARG_WORKFLOW, SIEMConstants.SIEM_REMOVE_EXCLUSION_RULE);
			reqArgs.put(StandardWorkflowHandler.ARG_REQUEST_NAME, caseName);
			reqArgs.put(SIEMConstants.REQUEST_NAME, caseName);
			
			Attributes<String, String> workflowArgs = new Attributes<>();
			workflowArgs.put(SIEMConstants.RULE_NAME, modifiedName);
			
			reqArgs.putAll(workflowArgs);
			
			Request req = new Request();
			RequestDefinition reqDef = context.getObject(RequestDefinition.class, SIEMConstants.WORKFLOW_REQUEST);
			req.setDefinition(reqDef);
			req.setEventDate(new Date(launchTime));
			req.setOwner(context.getObjectByName(Identity.class, SIEMConstants.SIEM_SERVICE));
			req.setName(caseName);
			req.setAttributes(reqDef, reqArgs);
			
			RequestManager.addRequest(context, req);
			
		} catch (Exception e) {
			
			log.error("Exception running delete modified exclusion rule task..." + e.toString());
		}
		
		log.trace("Exiting removeModifiedExclusionRule...");
	}
	
	/**
	 * Function to close the alert in Identity, update processed and date.
	 * 
	 * @param context
	 *            The SailPointContext.
	 * @param alertId
	 *            AlertId associated with the identity.
	 * @param closeDate
	 * @param result
	 * @param type
	 */
	public void closeAlert(SailPointContext context, String alertId, Date closeDate, String result, String type)
			throws GeneralException {
		
		log.trace("Entering closeAlert...");
		
		Alert alert = context.getObjectById(Alert.class, alertId);
		alert.setLastProcessed(closeDate);
		alert.setAttribute(SIEMConstants.RESULT, result);
		
		Attributes<String, Object> attrs = alert.getAttributes();
		attrs.put(SIEMConstants.RESULT, result);
		alert.setAttributes(attrs);
		
		AlertDefinition def = context.getObjectByName(AlertDefinition.class, SIEMConstants.SIEM_ALERT_DEFINITION);
		
		// need to fake up an action/result for UI rendering...set to notification only
		// with no email for now.
		// TODO - make this more tailored to each alert in the future
		AlertAction action = new AlertAction();
		action.setActionType(AlertDefinition.ActionType.NOTIFICATION);
		
		AlertAction.AlertActionResult res = new AlertAction.AlertActionResult();
		List<AlertNotification> notifications = new ArrayList<>();
		AlertAction.AlertNotification notification = new AlertAction.AlertNotification();
		notification.setName(SIEMConstants.SIEM_SERVICE);
		notification.setDisplayName(SIEMConstants.SIEM_SERVICE_ACCOUNT);
		notification.setEmailAddresses(new ArrayList<String>());
		notifications.add(notification);
		res.setNotifications(notifications);
		
		action.setResult(res);
		action.setCreated(alert.getCreated());
		action.setAlertDef(def);
		alert.addAction(action);
		
		context.saveObject(alert);
		context.commitTransaction();
		
		log.trace("Exiting closeAlert...");
	}
	
	/**
	 * Function to audit any provisioning actions taken by the SIEM plugin service.
	 *
	 * @param result
	 *            The result of the provisioning.
	 * @param iiqAlert
	 *            The IdentityIQ Alert object.
	 * @param applicationName
	 *            Name of the application being provisioned to.
	 * @param nativeId
	 *            Native ID of the account being provisioned.
	 * @param action
	 *            Action of the provisioning.
	 */
	public void auditProvisioning(String result, Alert iiqAlert, String applicationName, String nativeId,
			String action) {
		
		log.trace("Entering auditProvisioning...");
		
		AuditEvent event = new AuditEvent(SIEMConstants.SIEM_SERVICE, SIEMConstants.SIEM_PROVISIONING);
		if (null != nativeId) {
			
			event.setAccountName(nativeId);
		}
		
		if (null != applicationName) {
			
			event.setApplication(applicationName);
		}
		
		event.setTarget(iiqAlert.getTargetId());
		event.setString1((String) iiqAlert.getAttribute(SIEMConstants._ALERT_TYPE));
		
		int index = (int) iiqAlert.getAttribute(SIEMConstants._ALERT_TYPE_INDEX);
		if (index == 1 || index == 2 || index == 11) {
			
			event.setString2(SIEMConstants.SIEM_OPERATION + action);
		}
		
		if (index == 3 || index == 4 || index == 5 || index == 10) {
			
			event.setString2(SIEMConstants.SIEM_OPERATION_REMOVE);
			if (index == 3 || index == 10) {
				
				event.setAttributeValue((String) iiqAlert.getAttribute(SIEMConstants._TARGET_GROUP_NAME));
				event.setAttributeName((String) iiqAlert.getAttribute(SIEMConstants._TARGET_GROUP_TYPE));
			}
		}
		
		if (index == 6 || index == 7) {
			
			event.setString2(SIEMConstants.SIEM_OPERATION_PASSWORD);
		}
		Auditor.log(event);
		
		log.trace("Exiting auditProvisioning...");
	}
}
