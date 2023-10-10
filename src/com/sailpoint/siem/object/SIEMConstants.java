package com.sailpoint.siem.object;

/**
 * @author adam.creaney (Created on 4/17/17)
 * 
 *         Constants class.
 */
public class SIEMConstants {
	
	// IIQ Constants
	public static final String	PLUGIN_NAME									= "SIEMPlugin";
	public static final String	DEFAULT_WELCOME_MESSAGE						= "Hello World!";
	
	// Plugin Settings Constants
	public static final String	PURGE_BY_DAYS								= "purgeByDays";
	public static final String	PRIORITIZE_ALERTS							= "prioritizeByLevel";
	public static final String	DEFER_PROVISIONING							= "deferProvisioning";
	public static final String	PROVISIONING_WORKFLOW						= "provisioningWorkflow";
	public static final String	SYSLOG_LIMIT								= "syslogLimit";
	public static final String	AUDIT_EVENT_LIMIT							= "auditEventLimit";
	
	// Application Constants
	public static final String	APPLICATION									= "application";
	public static final String	APPLICATIONS								= "applications";
	public static final String	PROVISION									= "provision";
	public static final String	NAME										= "name";
	public static final String	DATE										= "date";
	public static final String	PLAN										= "plan";
	public static final String	PROJECT										= "project";
	public static final String	ID											= "id";
	public static final String	RESULT										= "Result";
	public static final String	IDENTITY									= "identity";
	public static final String	ACTION										= "action";
	public static final String	DISABLE										= "disable";
	public static final String	DELETE										= "delete";
	public static final String	LEVEL										= "level";
	public static final String	MEDIUM										= "Medium";
	public static final String	DEFAULT										= "default";
	public static final String	COUNT										= "count";
	public static final String	TEST										= "test";
	public static final String	WTVR										= "wtvr";
	public static final String	IDENTITY_ID									= "identityId";
	public static final String	APPLICATION_NAME							= "applicationName";
	public static final String	NATIVE_ID									= "nativeId";
	public static final String	CERTIFICATION								= "certification";
	public static final String	TARGET_GROUP_NAME							= "targetGroupName";
	public static final String	TARGET_GROUP_TYPE							= "targetGroupType";
	public static final String	DISABLE_GROUP								= "disableGroup";
	public static final String	DISABLE_ACCOUNTS							= "disableAccounts";
	public static final String	NONE										= "None";
	public static final String	ACTIVE_DIRECTORY_DIRECT						= "Active Directory - Direct";
	public static final String	PWD_LAST_SET								= "pwdLastSet";
	public static final String	AGGREGATION_STATE							= "aggregationState";
	public static final String	VALUE										= "value";
	public static final String	INSTANCE									= "instance";
	public static final String	NATIVE_IDENTITY								= "nativeIdentity";
	public static final String	RULE_NAME									= "ruleName";
	public static final String	REQUEST_NAME								= "requestName";
	public static final String	WORKFLOW_REQUEST							= "Workflow Request";
	public static final String	ENABLED										= "enabled";
	public static final String	AUDIT_CONFIG								= "AuditConfig";
	public static final String	AUDIT_EVENTS								= "AuditEvents";
	public static final String	IS_ALL										= "isAll";
	public static final String	IS_ACCOUNT									= "isAccount";
	public static final String	IS_ENTITLEMENT								= "isEntitlement";
	public static final String	IS_BULK_ENTITLEMENT							= "isBulkEntitlement";
	public static final String	IS_PASSWORD									= "isPassword";
	public static final String	IS_OVERRIDE									= "isOverride";
	public static final String	IS_GROUP_MEMBERSHIP							= "isGroupMembership";
	public static final String	IS_FULL_APPLICATION							= "isFullApplication";
	public static final String	MODIFIED									= "modified";
	public static final String	CREATED										= "created";
	public static final String	OVERVIEW									= "overview";
	
	// Application Constants [Symbols]
	public static final String	IDENTITY_DOT_NAME							= "identity.name";
	public static final String	IDENTITY_DOT_ID								= "identity.id";
	public static final String	APPLICATION_DOT_ID							= "application.id";
	public static final String	_NATIVE_ID									= "native_id";
	public static final String	_GROUP_NAME									= "group_name";
	public static final String	_GROUP_TYPE									= "group_type";
	public static final String	_SOURCE_APPLICATION							= "source_application";
	public static final String	_ALERT_TYPE									= "alert_type";
	public static final String	_ALERT_TYPE_INDEX							= "alert_type_index";
	public static final String	_USE_WORKFLOW								= "use_workflow";
	public static final String	_TARGET_GROUP_NAME							= "target_group_name";
	public static final String	_TARGET_GROUP_TYPE							= "target_group_type";
	
	// Application Constants [Endpoints]
	public static final String	IDENTITY_FOWARD_SLASH						= "identity/";
	public static final String	APPLICATION_FOWARD_SLASH					= "application/";
	
	// Messages
	public static final String	MSG_CREATED_ALERT_ID						= "Successfully created an alert Id.";
	public static final String	MSG_MISSING_PARAMETERS						= "Missing necessary parameters or value for REST service : ";
	
	// Date Constants
	public static final String	DATE_FORMAT									= "MM-dd-yyyy";
	
	// DB Constants
	public static final String	DB_ID										= "id";
	public static final String	DB_ALERT_TYPE								= "alert_type";
	public static final String	DB_ALERT_ID									= "alert_id";
	public static final String	DB_CREATED									= "created";
	public static final String	DB_NATIVE_ID								= "native_id";
	public static final String	DB_SOURCE_APPLICATION						= "source_application";
	public static final String	DB_TARGET_GROUP_NAME						= "target_group_name";
	public static final String	DB_TARGET_GROUP_TYPE						= "target_group_type";
	public static final String	DB_LEVEL									= "alert_level";
	public static final String	DB_ACTION									= "action";
	public static final String	DB_PROCESSED_DATE							= "processed_date";
	public static final String	DB_USE_WORKFLOW								= "use_workflow";
	public static final String	DB_TYPE_TOTALS								= "type_totals";
	public static final String	DB_ACCOUNT_METRICS							= "account_metrics";
	public static final String	DB_APPLICATION_METRICS						= "application_metrics";
	public static final String	DB_APPLICATION_COUNT						= "application_count";
	
	// Script Constants
	public static final String	SCRIPT_GROUP_VALUE							= "%%GROUP_VALUE%%";
	public static final String	SCRIPT_GROUP_TYPE							= "%%GROUP_TYPE%%";
	public static final String	SCRIPT_GROUP_APPLICATION_ID					= "%%GROUP_APPLICATION_ID%%";
	
	// Filter Constants
	public static final String	FILTER_NATIVE_IDENTITY						= "nativeIdentity";
	public static final String	FILTER_APPLICATION_NAME						= "application.name";
	public static final String	FILTER_NAME									= "name";
	public static final String	FILTER_VALUE								= "value";
	public static final String	FILTER_APPLICATION							= "application";
	public static final String	FILTER_AGGREGATION_STATE					= "aggregationState";
	public static final String	FILTER_ACTION								= "action";
	public static final String	FILTER_CREATED								= "created";
	public static final String	FILTER_TYPE									= "type";
	public static final String	FILTER_TARGET_ID							= "targetId";
	public static final String	FILTER_DISPLAY_NAME							= "displayName";
	public static final String	FILTER_QUICK_KEY							= "quickKey";
	
	// API Response Constants
	public static final String	RESPONSE_STATUS_SUCCESS						= "success";
	public static final String	RESPONSE_STATUS_FAIL						= "fail";
	public static final String	RESPONSE_STATUS_ERROR						= "success";
	
	// Status Constants
	public static final String	SUCCESS										= "Success";
	
	// Database Types
	public static final String	MICROSOFT_SQL_SERVER						= "microsoft sql server";
	public static final String	ORACLE										= "oracle";
	
	// Endpoint Constants
	public static final String	IDENTITY_ACCOUNT							= "identity/account";
	public static final String	IDENTITY_ACCOUNTS							= "identity/accounts";
	public static final String	IDENTITY_ENTITLEMENT						= "identity/entitlement";
	public static final String	IDENTITY_ENTITLEMENTS						= "identity/entitlements";
	public static final String	IDENTITY_ENTITLEMENTS_ALL					= "identity/entitlements-all";
	public static final String	IDENTITY_PASSWORD							= "identity/password";
	public static final String	IDENTITY_PASSWORDS							= "identity/passwords";
	public static final String	IDENTITY_CERTIFY							= "identity/certify";
	public static final String	IDENTITY_CERTIFY_ALL						= "identity/certify-all";
	public static final String	APPLICATION_GROUP							= "application/group";
	public static final String	APPLICATION_ACCOUNTS						= "application/accounts";
	public static final String	APPLICATION_CERTIFY_GROUP					= "application/certify-group";
	public static final String	APPLICATION_CERTIFY_ALL						= "application/certify-all";
	
	// SIEM Constants
	public static final String	SIEM_ALERT									= "SIEM Alert";
	public static final String	SIEM_APPLICATION_NAME						= "SIEM Application";
	public static final String	SIEM_OPERATION								= "SIEM Operation: ";
	public static final String	SIEM_OPERATION_REMOVE						= "SIEM Operation: Remove";
	public static final String	SIEM_OPERATION_PASSWORD						= "SIEM Operation: Password";
	public static final String	SIEM_IDENTITY_CERT							= "SIEM Identity Cert";
	public static final String	SIEM_APPLICATION_CERT						= "SIEM Application Cert";
	public static final String	SIEM_ALERT_DEFINITION						= "SIEM Alert Definition";
	public static final String	SIEM_SERVICE_ACCOUNT						= "SIEM Service Account";
	public static final String	SIEM_GROUP_CERT								= "SIEM Group Cert";
	public static final String	SIEM_SERVICE								= "siemservice";
	public static final String	SIEM_PROVISIONING							= "siemProvisioning";
	public static final String	SIEM_REMOVE_EXCLUSION_RULE					= "SIEM Remove Exclusion Rule";
	public static final String	SIEM_APPLICATION_OWNER_CERTIFICATION		= "SIEM Application Owner Certification";
	public static final String	SIEM_ENTITLEMENT_OWNER_CERTIFICATION		= "SIEM Entitlement Owner Certification";
	
	// SIEM Type Constants
	public static final String	SIEM_IDENTITY_ACCOUNT						= "SIEM Identity Account";
	public static final String	SIEM_IDENTITY_ACCOUNTS						= "SIEM Identity Accounts";
	public static final String	SIEM_IDENTITY_ENTITLEMENT					= "SIEM Identity Entitlement";
	public static final String	SIEM_IDENTITY_ENTITLEMENTS					= "SIEM Identity Entitlements";
	public static final String	SIEM_IDENTITY_ALL_ENTITLEMENTS				= "SIEM Identity All Entitlements";
	public static final String	SIEM_IDENTITY_PASSWORD						= "SIEM Identity Password";
	public static final String	SIEM_IDENTITY_PASSWORDS						= "SIEM Identity Passwords";
	public static final String	SIEM_IDENTITY_ACCOUNT_CERTIFICATION			= "SIEM Identity Account Certification";
	public static final String	SIEM_IDENTITY_CERTIFICATION					= "SIEM Identity Certification";
	public static final String	SIEM_APPLICATION_GROUP						= "SIEM Application Group";
	public static final String	SIEM_APPLICATION_ACCOUNTS					= "SIEM Application Accounts";
	public static final String	SIEM_APPLICATION_GROUP_CERTIFICATION		= "SIEM Application Group Certification";
	public static final String	SIEM_APPLICATION_CERTIFICATION				= "SIEM Application Certification";
	public static final String	UNDEFINED_SIEM_ALERT						= "Undefined SIEM Alert";
	public static final String	SIEM_IDENTITY_INFO							= "identityinfo";
	public static final String	IDENTITY_INFO_USERS							= "users";
	
	// IdentityInfo score related tokens
	public static final String	SCORE_TARGET_ID								= "targetId";
	public static final String	SCORE_REQUESTER_ID							= "requesterId";
	
	// Overview Service Constants
	public static final String	WORKFLOW_REQUESTS							= "Workflow Requests";
	public static final String	PROVISIONING_REQUESTS						= "Provisioning Requests";
	public static final String	ACCOUNT_DISABLE_REQUESTS					= "Account Disable Requests";
	public static final String	ACCOUNT_DELETE_REQUESTS						= "Account Delete Requests";
	public static final String	ENTITLEMENT_REMOVAL_REQUESTS				= "Entitlement Removal Requests";
	public static final String	CERTIFICATION_REQUESTS						= "Certification Requests";
	public static final String	APPLICATION_GROUPS_DISABLED					= "Application Groups Disabled";
	public static final String	APPLICATION_DISABLE_REQUESTS				= "Application Account Disable Requests";
	public static final String	APPLICATION_DELETE_REQUESTS					= "Application Account Delete Requests";
	public static final String	GROUP_CERTIFICATIONS_LAUNCHED				= "Group Certifications Launched";
	public static final String	APPLICATION_CERTIFICATIONS_LAUNCHED			= "Application Certifications Launched";
	public static final String	TOTAL_ALERTS								= "Total Alerts";
	public static final String	TOTAL_ALERTS_IN_LAST_24_HOURS				= "Total Alerts in Last 24 Hours";
	public static final String	TOTAL_IDENTITY_ALERTS						= "Total Identity Alerts";
	public static final String	TOTAL_IDENTITY_ALERTS_IN_LAST_24_HOURS		= "Total Identity Alerts in Last 24 Hours";
	public static final String	TOTAL_APPLICATION_ALERTS					= "Total Application Alerts";
	public static final String	TOTAL_APPLICATION_ALERTS_IN_LAST_24_HOURS	= "Total Application Alerts in Last 24 Hours";
	
	// Sort Constants
	public static final String	ASCENDING									= "ascending";
	public static final String	DESCENDING									= "descending";
	
	// Attribute Constants
	public static final String	ATTRIBUTE_ID								= "id";
	public static final String	ATTRIBUTE_CREATED							= "created";
	public static final String	ATTRIBUTE_OWNER								= "owner";
	public static final String	ATTRIBUTE_INTERFACE							= "interface";
	public static final String	ATTRIBUTE_SOURCE							= "source";
	public static final String	ATTRIBUTE_ACTION							= "action";
	public static final String	ATTRIBUTE_TARGET							= "target";
	public static final String	ATTRIBUTE_APPLICATION						= "application";
	public static final String	ATTRIBUTE_ACCOUNT_NAME						= "accountName";															// account_name
	public static final String	ATTRIBUTE_INSTANCE							= "instance";
	public static final String	ATTRIBUTE_ATTRIBUTE_NAME					= "attributeName";															// attribute_name
	public static final String	ATTRIBUTE_ATTRIBUTE_VALUE					= "attributeValue";															// attribute_value
	public static final String	ATTRIBUTE_TRACKING_ID						= "trackingId";																// tracking_id
	public static final String	ATTRIBUTE_ATTRIBUTES						= "attributes";																// Attributes
	public static final String	ATTRIBUTE_STRING_1							= "string1";
	public static final String	ATTRIBUTE_STRING_2							= "string2";
	public static final String	ATTRIBUTE_STRING_3							= "string3";
	public static final String	ATTRIBUTE_STRING_4							= "string4";
	public static final int		CONFIDENCER_ROLE_COUNT						= 3;
	public static final int		CONFIDENCER_LINK_COUNT						= 3;
	public static final int		CONFIDENCER_SUBMITTED_COUNT					= 5;
	public static final int		CONFIDENCER_TARGET_COUNT					= 5;
	public static final int		CONFIDENCER_DAY_COUNT						= 10;
	public static final int		CONFIDENCER_DAYS_SINCE_LOGIN_COUNT			= 10;
	public static final int		CONFIDENCER_TOTAL_CRITERIA					= 5;
	
	// Error Constants
	public static final String	ERROR_CODE_START_INDEX						= "IndexError";
	public static final String	ERROR_MESSAGE_START_INDEX					= "Invalid startIndex.";
	public static final String	ERROR_DETAILS_START_INDEX					= "startIndex should begin at index 1.";
	public static final String	ERROR_CODE_COUNT							= "CountError";
	public static final String	ERROR_MESSAGE_COUNT							= "Invalid count.";
	public static final String	ERROR_DETAILS_COUNT							= "count should be atleast 1.";
	public static final String	ERROR_CODE_START_TIME						= "TimeError";
	public static final String	ERROR_MESSAGE_START_TIME					= "Invalid startTime.";
	public static final String	ERROR_DETAILS_START_TIME					= "startTime should not be null or zero or negative long number(epoch).";
	public static final String	ERROR_CODE_END_TIME							= "TimeError";
	public static final String	ERROR_MESSAGE_END_TIME						= "Invalid endTime.";
	public static final String	ERROR_DETAILS_END_TIME						= "endTime should not be null or zero or negative long number(epoch).";
	public static final String	ERROR_CODE_DURATION							= "TimeError";
	public static final String	ERROR_MESSAGE_DURATION						= "Invalid duration.";
	public static final String	ERROR_DETAILS_DURATION						= "startTime should be less than endTime(epoch).";
}
