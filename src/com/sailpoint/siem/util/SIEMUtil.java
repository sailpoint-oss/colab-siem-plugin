package com.sailpoint.siem.util;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.sailpoint.siem.api.Confidencer;
import com.sailpoint.siem.object.AlertDataDTO;
import com.sailpoint.siem.object.AuditEventDTO;
import com.sailpoint.siem.object.IdentityInfoDTO;
import com.sailpoint.siem.object.IdentityLinkDTO;
import com.sailpoint.siem.object.SIEMAlertDTO;
import com.sailpoint.siem.object.SIEMConstants;

import sailpoint.api.SailPointContext;
import sailpoint.object.Filter;
import sailpoint.object.Link;
import sailpoint.object.QueryOptions;
import sailpoint.tools.GeneralException;

/**
 * @author adam.creaney (Created on 4/17/17)
 * 
 *         Utility class.
 */
public class SIEMUtil {
	
	// endpoint to displayname to index mapping...
	// identity/account = SIEM Identity Account = 1;
	// identity/accounts = SIEM Identity Accounts= 2;
	// identity/entitlement = SIEM Identity Entitlement = 3;
	// identity/entitlements = SIEM Identity Entitlements = 4;
	// identity/entitlements-all = SIEM Identity All Entitlements = 5;
	// identity/password = SIEM Identity Password = 6;
	// identity/passwords = SIEM Identity Passwords = 7;
	// identity/certify = SIEM Identity Account Certification = 8;
	// identity/certify-all = SIEM Identity Certification = 9;
	// application/group = SIEM Application Group = 10;
	// application/accounts = SIEM Application Accounts = 11;
	// application/certify-group = SIEM Application Group Certification = 12;
	// application/certify-all = SIEM Application Certification = 13;
	// default = 0;
	
	public static final Log log = LogFactory.getLog(SIEMUtil.class);
	
	/**
	 * Function to get the current timestamp.
	 *
	 * @return The timestamp.
	 */
	public static long now() {
		
		return new Date().getTime();
	}
	
	public static List<SIEMAlertDTO> sortAlerts(List<SIEMAlertDTO> alerts) {
		
		return alerts;
	}
	
	/**
	 * Function to validate attributes received in REST services via POST API call.
	 *
	 * @return String.
	 */
	public static String validateAttributes(Map<String, String> data, String service) {
		
		log.trace("Entering validateAttributes...");
		
		String val = "";
		
		if (service.equals(SIEMConstants.SIEM_IDENTITY_INFO)) {
			
			if (!data.containsKey(SIEMConstants.IDENTITY_INFO_USERS)) {
				
				val += "'" + SIEMConstants.IDENTITY_INFO_USERS + "', ";
			}
		} else {
			
			if (!data.containsKey(SIEMConstants.APPLICATION) || data.get(SIEMConstants.APPLICATION).isEmpty()) {
				
				val = "'" + SIEMConstants.APPLICATION + "', ";
			}
			
			if (!data.containsKey(SIEMConstants.DATE) || data.get(SIEMConstants.DATE).isEmpty()) {
				
				val += "'" + SIEMConstants.DATE + "', ";
			}
			
			if (service.equals(SIEMConstants.APPLICATION_GROUP)
					|| service.equals(SIEMConstants.APPLICATION_CERTIFY_GROUP)
					|| service.equals(SIEMConstants.IDENTITY_ENTITLEMENT)) {
				
				if (!data.containsKey(SIEMConstants._GROUP_NAME) || data.get(SIEMConstants._GROUP_NAME).isEmpty()) {
					
					val += "'" + SIEMConstants._GROUP_NAME + "', ";
				}
				
				if (!data.containsKey(SIEMConstants._GROUP_TYPE) || data.get(SIEMConstants._GROUP_TYPE).isEmpty()) {
					
					val += "'" + SIEMConstants._GROUP_TYPE + "', ";
				}
			}
			
			if (service.equals(SIEMConstants.IDENTITY_ENTITLEMENT) || service.equals(SIEMConstants.IDENTITY)) {
				
				if (!data.containsKey(SIEMConstants._NATIVE_ID) || data.get(SIEMConstants._NATIVE_ID).isEmpty()) {
					
					val += "'" + SIEMConstants._NATIVE_ID + "', ";
				}
			}
			
			if (!data.containsKey(SIEMConstants.ACTION) || data.get(SIEMConstants.ACTION).isEmpty()) {
				
				// Set default action to Disable
				data.put(SIEMConstants.ACTION, SIEMConstants.DISABLE);
			}
			
			if (!data.containsKey(SIEMConstants.LEVEL) || data.get(SIEMConstants.LEVEL).isEmpty()) {
				
				// Set default level to Medium
				data.put(SIEMConstants.LEVEL, SIEMConstants.MEDIUM);
			}
			
		}
		
		if (!val.isEmpty()) {
			
			val = val.trim().substring(val.trim().length() - 1, val.trim().length()).equals(",")
					? val.trim().substring(0, val.trim().length() - 1)
					: val;
		} else {
			
			val = SIEMConstants.SUCCESS;
		}
		
		log.trace("Exiting validateAttributes...");
		return val;
	}
	
	/**
	 * Function that returns pretty display name of the IdentityIQ Alert object
	 * created.
	 *
	 * @param Type
	 *            type of the endpoint
	 * @return The displayName of the IdentityIQ object.
	 */
	public static String getAlertDisplayName(String type) {
		
		log.trace("Entering getAlertDisplayName...");
		String displayName = "";
		
		switch (type) {
			
			case SIEMConstants.IDENTITY_ACCOUNT:
				displayName = SIEMConstants.SIEM_IDENTITY_ACCOUNT;
				break;
			
			case SIEMConstants.IDENTITY_ACCOUNTS:
				displayName = SIEMConstants.SIEM_IDENTITY_ACCOUNTS;
				break;
			
			case SIEMConstants.IDENTITY_ENTITLEMENT:
				displayName = SIEMConstants.SIEM_IDENTITY_ENTITLEMENT;
				break;
			
			case SIEMConstants.IDENTITY_ENTITLEMENTS:
				displayName = SIEMConstants.SIEM_IDENTITY_ENTITLEMENTS;
				break;
			
			case SIEMConstants.IDENTITY_ENTITLEMENTS_ALL:
				displayName = SIEMConstants.SIEM_IDENTITY_ALL_ENTITLEMENTS;
				break;
			
			case SIEMConstants.IDENTITY_PASSWORD:
				displayName = SIEMConstants.SIEM_IDENTITY_PASSWORD;
				break;
			
			case SIEMConstants.IDENTITY_PASSWORDS:
				displayName = SIEMConstants.SIEM_IDENTITY_PASSWORDS;
				break;
			
			case SIEMConstants.IDENTITY_CERTIFY:
				displayName = SIEMConstants.SIEM_IDENTITY_ACCOUNT_CERTIFICATION;
				break;
			
			case SIEMConstants.IDENTITY_CERTIFY_ALL:
				displayName = SIEMConstants.SIEM_IDENTITY_CERTIFICATION;
				break;
			
			case SIEMConstants.APPLICATION_GROUP:
				displayName = SIEMConstants.SIEM_APPLICATION_GROUP;
				break;
			
			case SIEMConstants.APPLICATION_ACCOUNTS:
				displayName = SIEMConstants.SIEM_APPLICATION_ACCOUNTS;
				break;
			
			case SIEMConstants.APPLICATION_CERTIFY_GROUP:
				displayName = SIEMConstants.SIEM_APPLICATION_GROUP_CERTIFICATION;
				break;
			
			case SIEMConstants.APPLICATION_CERTIFY_ALL:
				displayName = SIEMConstants.SIEM_APPLICATION_CERTIFICATION;
				break;
			
			default:
				displayName = SIEMConstants.UNDEFINED_SIEM_ALERT;
				break;
		}
		
		log.trace("Exiting getAlertDisplayName with displayName : " + displayName);
		return displayName;
	}
	
	/**
	 * Function to return an integer index that is used to determine the action
	 * taken on the alert, which is based on the end point that generated the alert.
	 *
	 * @param displayName
	 *            displayName of the alert.
	 * @return the index of alert for use in determining action.
	 */
	public static int getAlertTypeIndex(String displayName) {
		
		log.trace("Entering getAlertTypeIndex...");
		int ret = 0;
		
		switch (displayName) {
			
			case SIEMConstants.SIEM_IDENTITY_ACCOUNT:
				ret = 1;
				break;
			
			case SIEMConstants.SIEM_IDENTITY_ACCOUNTS:
				ret = 2;
				break;
			
			case SIEMConstants.SIEM_IDENTITY_ENTITLEMENT:
				ret = 3;
				break;
			
			case SIEMConstants.SIEM_IDENTITY_ENTITLEMENTS:
				ret = 4;
				break;
			
			case SIEMConstants.SIEM_IDENTITY_ALL_ENTITLEMENTS:
				ret = 5;
				break;
			
			case SIEMConstants.SIEM_IDENTITY_PASSWORD:
				ret = 6;
				break;
			
			case SIEMConstants.SIEM_IDENTITY_PASSWORDS:
				ret = 7;
				break;
			
			case SIEMConstants.SIEM_IDENTITY_ACCOUNT_CERTIFICATION:
				ret = 8;
				break;
			
			case SIEMConstants.SIEM_IDENTITY_CERTIFICATION:
				ret = 9;
				break;
			
			case SIEMConstants.SIEM_APPLICATION_GROUP:
				ret = 10;
				break;
			
			case SIEMConstants.SIEM_APPLICATION_ACCOUNTS:
				ret = 11;
				break;
			
			case SIEMConstants.SIEM_APPLICATION_GROUP_CERTIFICATION:
				ret = 12;
				break;
			
			case SIEMConstants.SIEM_APPLICATION_CERTIFICATION:
				ret = 13;
				break;
			
			default:
				ret = 0;
				break;
		}
		
		log.trace("Exiting getAlertTypeIndex with : " + ret);
		return ret;
	}
	
	/**
	 * Function to build identity info for all account names included in the
	 * incoming JSON string.
	 * 
	 * @param data
	 * @return
	 */
	public static IdentityInfoDTO getIdentityInfo(SailPointContext context, Map<String, String> data)
			throws JSONException, GeneralException {
		
		log.trace("Entering getIdentityInfo...");
		IdentityInfoDTO identityInfoDTO = new IdentityInfoDTO();
		
		JSONObject usersObject = new JSONObject(data);
		JSONArray users = (JSONArray) usersObject.getJSONArray(SIEMConstants.IDENTITY_INFO_USERS);
		
		Map<String, Map<String, IdentityLinkDTO>> linksMap = new HashMap<>();
		
		for (int i = 0; i < users.length(); i++) {
			
			JSONObject userObj = users.getJSONObject(i);
			String nativeIdentity = userObj.getString(SIEMConstants.NATIVE_IDENTITY);
			log.debug("nativeIdentity : " + nativeIdentity);
			
			QueryOptions qo = new QueryOptions();
			Filter nativeIdentityFilter = Filter.eq(SIEMConstants.FILTER_NATIVE_IDENTITY, nativeIdentity);
			qo.addFilter(nativeIdentityFilter);
			
			List<String> attrs = new ArrayList<>();
			attrs.add(SIEMConstants.ID);
			attrs.add(SIEMConstants.NATIVE_IDENTITY);
			attrs.add(SIEMConstants.IDENTITY_DOT_ID);
			attrs.add(SIEMConstants.APPLICATION_DOT_ID);
			attrs.add(SIEMConstants.MODIFIED);
			attrs.add(SIEMConstants.CREATED);
			
			Map<String, IdentityLinkDTO> linkMap = new HashMap<>();
			Iterator<?> it = context.search(Link.class, qo, attrs);
			while (it.hasNext()) {
				
				Object[] link = (Object[]) it.next();
				String linkId = (String) link[0];
				String linkNativeIdentity = (String) link[1];
				String linkIdentityId = (String) link[2];
				String linkApplicationId = (String) link[3];
				Date linkModified = (Date) link[4];
				Date linkCreated = (Date) link[5];
				
				if (log.isDebugEnabled()) {
					
					log.debug("Link info :");
					log.debug("link id :             " + linkId);
					log.debug("linkNativeIdentity :  " + linkNativeIdentity);
					log.debug("linkIdentityId :      " + linkIdentityId);
					log.debug("linkApplicationId :   " + linkApplicationId);
					log.debug("linkModified date :   " + linkModified.toString());
					log.debug("linkCreated date :    " + linkCreated.toString());
				}
				
				IdentityLinkDTO identityLink = new IdentityLinkDTO(linkNativeIdentity, linkIdentityId,
						linkApplicationId, linkModified.toString(), linkCreated.toString());
				linkMap.put(linkId, identityLink);
			}
			
			linksMap.put(nativeIdentity, linkMap);
			
			log.debug("The linksMap is: " + linksMap.toString());
			sailpoint.tools.Util.flushIterator(it);
		}
		
		identityInfoDTO = buildIdentityInfoFromMap(context, linksMap);
		log.trace("Exiting getIdentityInfo...");
		return identityInfoDTO;
	}
	
	/**
	 * Function to build out the returned JSON map of possible Identities that match
	 * the account names send to the /identityinfo endpoint, that includes the
	 * nativeIds requested, the identities that could potentially correlate to that
	 * account name, and the 'confidence' score that the Identity is the one being
	 * requested.
	 *
	 * @param context
	 *            The SailPointContext.
	 * @param linksMap
	 *            Map of the account names to the map of link ids to IdentityLink
	 *            objects representing interesting info form the SailPoint Link
	 *            object it is summarizing.
	 * @return
	 * @throws GeneralException
	 */
	public static IdentityInfoDTO buildIdentityInfoFromMap(SailPointContext context,
			Map<String, Map<String, IdentityLinkDTO>> linksMap) throws GeneralException {
		
		log.trace("Entering buildIdentityInfoFromMap...");
		
		IdentityInfoDTO identityInfoDTO = new IdentityInfoDTO();
		List<IdentityInfoDTO.NativeIdentity> nativeIdentities = new ArrayList<>();
		
		for (Map.Entry<String, Map<String, IdentityLinkDTO>> entry : linksMap.entrySet()) {
			
			String nativeIdentity = entry.getKey();
			log.debug("nativeIdentity : " + nativeIdentity);
			Map<String, IdentityLinkDTO> value = (Map<String, IdentityLinkDTO>) entry.getValue();
			
			Confidencer confidencer = new Confidencer(context, value);
			
			Map<String, Double> linksWithConfidence = confidencer.evaluate();
			
			IdentityInfoDTO.NativeIdentity iiNativeIdentity = new IdentityInfoDTO.NativeIdentity();
			iiNativeIdentity.setNativeIdentity(nativeIdentity);
			
			List<IdentityInfoDTO.Identity> results = new ArrayList<>();
			for (Map.Entry<String, Double> entryLink : linksWithConfidence.entrySet()) {
				
				String identityName = entryLink.getKey();
				log.debug("identityName : " + identityName);
				
				double confidence = entryLink.getValue();
				log.debug("confidence : " + confidence);
				
				IdentityInfoDTO.Identity iiIdentity = new IdentityInfoDTO.Identity(identityName, confidence);
				results.add(iiIdentity);
			}
			iiNativeIdentity.setResults(results);
			nativeIdentities.add(iiNativeIdentity);
		}
		identityInfoDTO.setIdentities(nativeIdentities);
		
		if (log.isDebugEnabled()) {
			
			log.debug("The identity info is: " + identityInfoDTO.toString());
		}
		
		log.trace("Exiting buildIdentityInfoFromMap...");
		return identityInfoDTO;
	}
	
	/**
	 * Function to return a list of attributes for AuditEvent object. These
	 * attributes are requested from DB.
	 * 
	 * @return List of AuditEvent attributes.
	 */
	public static List<String> getAttributesForAuditEvent() {
		
		log.trace("Entering getAttributesForAuditEvent...");
		
		// List of attributes to be queried from DB.
		List<String> attributes = new ArrayList<>();
		
		attributes.add(SIEMConstants.ATTRIBUTE_ID);
		attributes.add(SIEMConstants.ATTRIBUTE_CREATED);
		attributes.add(SIEMConstants.ATTRIBUTE_OWNER);
		attributes.add(SIEMConstants.ATTRIBUTE_INTERFACE);
		attributes.add(SIEMConstants.ATTRIBUTE_SOURCE);
		attributes.add(SIEMConstants.ATTRIBUTE_ACTION);
		attributes.add(SIEMConstants.ATTRIBUTE_TARGET);
		attributes.add(SIEMConstants.ATTRIBUTE_APPLICATION);
		attributes.add(SIEMConstants.ATTRIBUTE_ACCOUNT_NAME);
		attributes.add(SIEMConstants.ATTRIBUTE_INSTANCE);
		attributes.add(SIEMConstants.ATTRIBUTE_ATTRIBUTE_NAME);
		attributes.add(SIEMConstants.ATTRIBUTE_ATTRIBUTE_VALUE);
		attributes.add(SIEMConstants.ATTRIBUTE_TRACKING_ID);
		attributes.add(SIEMConstants.ATTRIBUTE_ATTRIBUTES);
		attributes.add(SIEMConstants.ATTRIBUTE_STRING_1);
		attributes.add(SIEMConstants.ATTRIBUTE_STRING_2);
		attributes.add(SIEMConstants.ATTRIBUTE_STRING_3);
		attributes.add(SIEMConstants.ATTRIBUTE_STRING_4);
		
		log.trace("Exiting getAttributesForAuditEvent...");
		return attributes;
	}
	
	/**
	 * Function to return a TempAuditEvent object that is extracted out of the
	 * auditEvent object (Mapper).
	 * 
	 * @param auditEvent
	 * @return TempAuditEvent object constructed out of auditEvent object.
	 */
	public static AuditEventDTO setTempAuditEvent(Object[] auditEvent) {
		
		log.trace("Entering setTempAuditEvent...");
		
		AuditEventDTO tempAuditEvent = new AuditEventDTO();
		
		// TODO : Add some sanitization or validation to ensure valid data assignment.
		tempAuditEvent.setId(getNullSafe(auditEvent[0]));
		tempAuditEvent.setCreated((Date) auditEvent[1]);
		tempAuditEvent.setOwner(getNullSafe(auditEvent[2]));
		tempAuditEvent.setInterface(getNullSafe(auditEvent[3]));
		tempAuditEvent.setSource(getNullSafe(auditEvent[4]));
		tempAuditEvent.setAction(getNullSafe(auditEvent[5]));
		tempAuditEvent.setTarget(getNullSafe(auditEvent[6]));
		tempAuditEvent.setApplication(getNullSafe(auditEvent[7]));
		tempAuditEvent.setAccountName(getNullSafe(auditEvent[8]));
		tempAuditEvent.setInstance(getNullSafe(auditEvent[9]));
		tempAuditEvent.setAttributeName(getNullSafe(auditEvent[10]));
		tempAuditEvent.setAttributeValue((getNullSafe(auditEvent[11])));
		tempAuditEvent.setTrackingId(getNullSafe(auditEvent[12]));
		tempAuditEvent.setAttributes(getNullSafe(auditEvent[13]));
		tempAuditEvent.setString1(getNullSafe(auditEvent[14]));
		tempAuditEvent.setString2(getNullSafe(auditEvent[15]));
		tempAuditEvent.setString3(getNullSafe(auditEvent[16]));
		tempAuditEvent.setString4(getNullSafe(auditEvent[17]));
		
		log.trace("Exiting setTempAuditEvent...");
		return tempAuditEvent;
	}
	
	/**
	 * Function to check if an object is null.
	 * 
	 * @param obj
	 *            the object to be checked.
	 * @return String representation of the object if not null, else an empty
	 *         string.
	 */
	public static String getNullSafe(Object obj) {
		
		String ret = "";
		if (null != obj) {
			
			ret = obj.toString();
		}
		
		return ret;
	}
	
	/**
	 * Function to create an SIEMAlert from given resultset.
	 * 
	 * @param resultSet
	 * @return the SIEMAlert
	 * @throws SQLException
	 */
	public static SIEMAlertDTO alertFromResultSet(ResultSet resultSet) throws SQLException {
		
		SIEMAlertDTO siemAlert = new SIEMAlertDTO();
		
		siemAlert.setId(resultSet.getString(SIEMConstants.DB_ID));
		siemAlert.setAlertType(resultSet.getString(SIEMConstants.DB_ALERT_TYPE));
		siemAlert.setAlertId(resultSet.getString(SIEMConstants.DB_ALERT_ID));
		siemAlert.setCreated(resultSet.getLong(SIEMConstants.DB_CREATED));
		siemAlert.setNativeId(resultSet.getString(SIEMConstants.DB_NATIVE_ID));
		siemAlert.setSourceApplication(resultSet.getString(SIEMConstants.DB_SOURCE_APPLICATION));
		siemAlert.setTargetGroupName(resultSet.getString(SIEMConstants.DB_TARGET_GROUP_NAME));
		siemAlert.setTargetGroupType(resultSet.getString(SIEMConstants.DB_TARGET_GROUP_TYPE));
		siemAlert.setLevel(resultSet.getString(SIEMConstants.DB_LEVEL));
		siemAlert.setAction(resultSet.getString(SIEMConstants.DB_ACTION));
		siemAlert.setProcessedDate(resultSet.getLong(SIEMConstants.DB_PROCESSED_DATE));
		siemAlert.setAlertType(resultSet.getString(SIEMConstants.DB_ALERT_TYPE));
		
		return siemAlert;
	}
	
	/**
	 * Utility method to update counts
	 * 
	 * @param alertDataList
	 * @param fieldName
	 */
	public static void updateTotal(List<AlertDataDTO> alertDataList, String fieldName) {
		
		log.trace("Entering updateTotal...");
		
		int previousTotal = 0;
		AlertDataDTO oldAlertData = null;
		
		for (AlertDataDTO alertData : alertDataList) {
			
			if (alertData.getDisplayName().equalsIgnoreCase(fieldName)) {
				
				previousTotal = alertData.getCount();
				oldAlertData = alertData;
			}
		}
		
		int newTotal = previousTotal + 1;
		AlertDataDTO updatedAlertData = new AlertDataDTO(fieldName, newTotal);
		if (oldAlertData != null) {
			
			alertDataList.remove(oldAlertData);
		}
		
		log.trace("Exiting updateTotal...");
		alertDataList.add(updatedAlertData);
	}
	
	/**
	 * Function to convert a String value into a primitive integer value. If the
	 * string is invalid, the value of the "def" argument is returned.
	 * 
	 * @param val
	 *            Integer value in string representation.
	 * @param def
	 *            Default value to be return in case the parsing fails.
	 * @return Integer value of the converted string.
	 */
	public static int getInteger(String val, int def) {
		
		int intVal = def;
		
		if (val != null && val.length() > 0) {
			
			try {
				
				intVal = Integer.parseInt(val);
			} catch (NumberFormatException e) {
				
				// Ignore and return default.
			}
		}
		
		return intVal;
	}
	
	/**
	 * Function to convert a String value into a primitive long value. If the string
	 * is invalid, the value of the "def" argument is returned.
	 * 
	 * @param val
	 *            Long value in string representation.
	 * @param def
	 *            Default value to be return in case the parsing fails.
	 * @return Long value of the converted string.
	 */
	public static long getLong(String val, long def) {
		
		long longVal = def;
		
		if (val != null && val.length() > 0) {
			
			try {
				
				longVal = Long.parseLong(val);
			} catch (NumberFormatException e) {
				
				// Ignore and return default.
			}
		}
		
		return longVal;
	}
	
	/**
	 * Function to get API limit. Limit will be always 1 < min(apiLimit,
	 * manifestLimit) < systemLimit (1000).
	 * 
	 * @param apiLimit
	 *            Limit sent in the API call.
	 * @param manifestLimit
	 *            Limit set in the plugin manifest file.
	 * @param systemLimit
	 *            System limit (1000).
	 * @return
	 */
	public static int getLimit(int apiLimit, int manifestLimit, int systemLimit) {
		
		int newExtLimit = Math.min(apiLimit, manifestLimit);
		
		if (1 < newExtLimit && newExtLimit <= systemLimit) {
			
			// In bounds.
			return newExtLimit;
		} else if (newExtLimit > systemLimit) {
			
			// Upper limit.
			return systemLimit;
		} else {
			
			// Lower limit.
			return 1;
		}
	}
}
