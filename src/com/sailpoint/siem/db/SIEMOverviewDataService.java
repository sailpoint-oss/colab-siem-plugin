package com.sailpoint.siem.db;

import java.lang.reflect.Type;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.sailpoint.iplus.DBUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.sailpoint.siem.object.AlertDataDTO;
import com.sailpoint.siem.object.SIEMAlertDTO;
import com.sailpoint.siem.object.SIEMConstants;
import com.sailpoint.siem.util.SIEMUtil;

import sailpoint.api.SailPointContext;
import sailpoint.api.SailPointFactory;
import sailpoint.object.Alert;
import sailpoint.object.Filter;
import sailpoint.object.QueryOptions;
import sailpoint.plugin.PluginBaseHelper;
import sailpoint.plugin.PluginContext;
import sailpoint.tools.GeneralException;

/**
 * @author chelsea.mcfarland (Created on 1/11/2019)
 * 
 *         SIEMOverviewDataService class.
 */
public class SIEMOverviewDataService {
	
	private static Log		log	= LogFactory.getLog(SIEMOverviewDataService.class);
	
	/**
	 * The plugin context
	 */
	private PluginContext	pluginContext;
	
	/**
	 * Default constructor
	 */
	public SIEMOverviewDataService(PluginContext pluginContext) {
		
		this.pluginContext = pluginContext;
	}
	
	/**
	 * Function to retrieve alert data objects from the siem_alert_overview table.
	 * 
	 * @param countType
	 *            the type of data to retrieve.
	 * @return List<AlertData> the objects.
	 * @throws GeneralException
	 */
	public List<AlertDataDTO> getAlertCount(String countType) throws GeneralException {
		
		log.trace("Entering getAlertCount...");
		
		List<AlertDataDTO> alertCountsList;
		
		if (countType.equalsIgnoreCase(SIEMConstants.OVERVIEW)) {
			
			alertCountsList = getAlertCount();
		} else {
			
			alertCountsList = getAlertOverviewData(countType);
		}
		
		log.trace("Exiting getAlertCount...");
		return alertCountsList;
	}
	
	/**
	 * Function called whenever a new SIEM alert is created updates the alert counts
	 * in siem_overview_data.
	 * 
	 * @param data
	 * @throws GeneralException
	 */
	public void updateSiemMetrics(SIEMAlertDTO data) throws GeneralException {
		
		log.trace("Entering updateSiemMetrics...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			
			connection = pluginContext.getConnection();
			
			String typeTotalsJson = updateTypeTotals(data);
			String accountMetricsJson = updateAccountMetrics(data);
			String applicationMetricsJson = updateApplicationMetrics(data);
			String applicationCountJson = updateApplicationCount(data);
			
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.UPDATE_OVERVIEW_DATA,
					typeTotalsJson, accountMetricsJson, applicationMetricsJson, applicationCountJson);
			statement.executeUpdate();
		} catch (SQLException e) {
			
			log.error("Error in updateSiemMetrics : " + e);
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				log.error("Error in closing DB Objects : " + e);
			}
		}
		
		log.trace("Exiting updateSiemMetrics...");
	}
	
	/**
	 * Function to get the application_count column from siem_overview_data.
	 * 
	 * @return List<AlertData> the applications_count list
	 * @throws GeneralException
	 */
	private List<AlertDataDTO> getAlertOverviewData(String column) throws GeneralException {
		
		log.trace("Entering getAlertOverviewData...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		List<AlertDataDTO> applicationMetrics = new ArrayList<>();
		
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.GET_OVERVIEW_DATA);
			ResultSet resultSet = statement.executeQuery();
			
			Gson gson = new Gson();
			Type type = new TypeToken<List<AlertDataDTO>>() {}.getType();
			while (resultSet.next()) {
				
				applicationMetrics = gson.fromJson(resultSet.getString(column), type);
			}
			
		} catch (SQLException e) {
			
			log.error("Error in getAlertOverviewData : " + e);
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				log.error("Error in closing DB Objects : " + e);
			}
		}
		
		log.trace("Exiting getAlertOverviewData...");
		return applicationMetrics;
	}
	
	/**
	 * Function to retrieve alert overview data counts from the spt_alert table.
	 * 
	 * @return List<AlertData> the overview data
	 * @throws GeneralException
	 */
	private List<AlertDataDTO> getAlertCount() throws GeneralException {
		
		log.trace("Entering getAlertCount...");
		
		Date today = new Date();
		
		List<AlertDataDTO> alertCountsList = new ArrayList<>();
		int totalAlerts = getAlertCount(null, null);
		int totalAlertsTwentyFourHours = getAlertCount(null, today);
		int totalIdentityAlerts = getAlertCount(SIEMConstants.IDENTITY, null);
		int totalIdentityAlertsTwentyFourHours = getAlertCount(SIEMConstants.IDENTITY, today);
		int totalApplicationAlerts = getAlertCount(SIEMConstants.APPLICATION, null);
		int totalApplicationAlertsTwentyFourHours = getAlertCount(SIEMConstants.APPLICATION, today);
		
		alertCountsList.add(new AlertDataDTO(SIEMConstants.TOTAL_ALERTS, totalAlerts));
		alertCountsList.add(new AlertDataDTO(SIEMConstants.TOTAL_ALERTS_IN_LAST_24_HOURS, totalAlertsTwentyFourHours));
		alertCountsList.add(new AlertDataDTO(SIEMConstants.TOTAL_IDENTITY_ALERTS, totalIdentityAlerts));
		alertCountsList.add(new AlertDataDTO(SIEMConstants.TOTAL_IDENTITY_ALERTS_IN_LAST_24_HOURS,
				totalIdentityAlertsTwentyFourHours));
		alertCountsList.add(new AlertDataDTO(SIEMConstants.TOTAL_APPLICATION_ALERTS, totalApplicationAlerts));
		alertCountsList.add(new AlertDataDTO(SIEMConstants.TOTAL_APPLICATION_ALERTS_IN_LAST_24_HOURS,
				totalApplicationAlertsTwentyFourHours));
		
		log.trace("Exiting getAlertCount...");
		return alertCountsList;
	}
	
	/**
	 * Function to get the alert count for the alerts overview.
	 * 
	 * @param type
	 * @param today
	 * @return
	 * @throws GeneralException
	 */
	private int getAlertCount(String type, Date today) throws GeneralException {
		
		log.trace("Entering getAlertCount...");
		
		int alertCount;
		SailPointContext sailPointContext = SailPointFactory.getCurrentContext();
		
		QueryOptions query = new QueryOptions();
		Filter alertTypeFilter = Filter.eq(SIEMConstants.FILTER_TYPE, SIEMConstants.SIEM_ALERT);
		List<Filter> filters = new ArrayList<Filter>();
		filters.add(alertTypeFilter);
		
		if (today != null) {
			
			Date yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
			Filter dateFilter = Filter.gt(SIEMConstants.FILTER_CREATED, yesterday);
			filters.add(dateFilter);
		}
		
		if (type != null) {
			
			Filter siemTypeFilter = Filter.like(SIEMConstants.FILTER_DISPLAY_NAME, type);
			filters.add(siemTypeFilter);
		}
		
		Filter filter = Filter.and(filters);
		query.add(filter);
		alertCount = sailPointContext.countObjects(Alert.class, query);
		
		log.trace("Exiting getAlertCount...");
		return alertCount;
	}
	
	/**
	 * Function to update the type_totals column in siem_overview_data.
	 *
	 * @param data
	 * @return String updated JSON to be saved back in siem_overview_data.
	 * @throws GeneralException
	 */
	private String updateTypeTotals(SIEMAlertDTO data) throws GeneralException {
		
		log.trace("Entering updateTypeTotals...");
		
		List<AlertDataDTO> typeTotals;
		String endpointType = data.getAlertType();
		String typeTotalsJson;
		
		Gson gson = new Gson();
		Type type = new TypeToken<List<AlertDataDTO>>() {}.getType();
		typeTotals = getAlertOverviewData(SIEMConstants.DB_TYPE_TOTALS);
		
		SIEMUtil.updateTotal(typeTotals, endpointType);
		typeTotalsJson = gson.toJson(typeTotals, type);
		
		log.trace("Exiting updateTypeTotals...");
		return typeTotalsJson;
	}
	
	/**
	 * Function to update the account_metrics column in siem_overview_data.
	 * 
	 * @param data
	 * @return String updated JSON to be saved back in siem_overview_data.
	 * @throws GeneralException
	 */
	private String updateAccountMetrics(SIEMAlertDTO data) throws GeneralException {
		
		log.trace("Entering updateAccountMetrics...");
		
		List<AlertDataDTO> accountMetrics;
		String endpointType = data.getAlertType();
		String action = data.getAction();
		String accountMetricsJson;
		
		Gson gson = new Gson();
		Type type = new TypeToken<List<AlertDataDTO>>() {}.getType();
		
		accountMetrics = getAlertOverviewData(SIEMConstants.DB_ACCOUNT_METRICS);
		
		if (endpointType.contains(SIEMConstants.IDENTITY)) {
			
			if (data.isOverride()) {
				
				SIEMUtil.updateTotal(accountMetrics, SIEMConstants.WORKFLOW_REQUESTS);
			} else {
				
				SIEMUtil.updateTotal(accountMetrics, SIEMConstants.PROVISIONING_REQUESTS);
			}
			
			if (action.equalsIgnoreCase(SIEMConstants.DISABLE)) {
				
				SIEMUtil.updateTotal(accountMetrics, SIEMConstants.ACCOUNT_DISABLE_REQUESTS);
			} else if (action.equalsIgnoreCase(SIEMConstants.DELETE)) {
				
				SIEMUtil.updateTotal(accountMetrics, SIEMConstants.ACCOUNT_DELETE_REQUESTS);
			}
			
			if (endpointType.contains(SIEMConstants.IDENTITY_ENTITLEMENT)) {
				
				SIEMUtil.updateTotal(accountMetrics, SIEMConstants.ENTITLEMENT_REMOVAL_REQUESTS);
			} else if (endpointType.contains(SIEMConstants.IDENTITY_CERTIFY)) {
				
				SIEMUtil.updateTotal(accountMetrics, SIEMConstants.CERTIFICATION_REQUESTS);
			}
		}
		accountMetricsJson = gson.toJson(accountMetrics, type);
		
		log.trace("Exiting updateAccountMetrics...");
		return accountMetricsJson;
	}
	
	/**
	 * Function to update the application_metrics column in siem_overview_data.
	 * 
	 * @param data
	 * @return String updated JSON to be saved back in siem_overview_data
	 * @throws GeneralException
	 */
	private String updateApplicationMetrics(SIEMAlertDTO data) throws GeneralException {
		
		log.trace("Entering updateApplicationMetrics...");
		
		List<AlertDataDTO> applicationMetrics;
		String endpointType = data.getAlertType();
		String action = data.getAction();
		String applicationMetricsJson;
		
		Gson gson = new Gson();
		Type type = new TypeToken<List<AlertDataDTO>>() {}.getType();
		
		applicationMetrics = getAlertOverviewData(SIEMConstants.DB_APPLICATION_METRICS);
		if (endpointType.contains(SIEMConstants.APPLICATION)) {
			
			if (endpointType.contains(SIEMConstants.APPLICATION_GROUP)) {
				
				SIEMUtil.updateTotal(applicationMetrics, SIEMConstants.APPLICATION_GROUPS_DISABLED);
			}
			
			if (endpointType.contains(SIEMConstants.APPLICATION_ACCOUNTS)) {
				
				if (action.equalsIgnoreCase(SIEMConstants.DISABLE)) {
					
					SIEMUtil.updateTotal(applicationMetrics, SIEMConstants.APPLICATION_DISABLE_REQUESTS);
				} else if (action.equalsIgnoreCase(SIEMConstants.DELETE)) {
					
					SIEMUtil.updateTotal(applicationMetrics, SIEMConstants.APPLICATION_DELETE_REQUESTS);
				}
			}
			
			if (endpointType.contains(SIEMConstants.APPLICATION_CERTIFY_GROUP)) {
				
				SIEMUtil.updateTotal(applicationMetrics, SIEMConstants.GROUP_CERTIFICATIONS_LAUNCHED);
			} else if (endpointType.contains(SIEMConstants.APPLICATION_CERTIFY_ALL)) {
				
				SIEMUtil.updateTotal(applicationMetrics, SIEMConstants.APPLICATION_CERTIFICATIONS_LAUNCHED);
			}
		}
		applicationMetricsJson = gson.toJson(applicationMetrics, type);
		
		log.trace("Exiting updateApplicationMetrics...");
		return applicationMetricsJson;
	}
	
	/**
	 * Function to update the application_count column in siem_overview_data.
	 * 
	 * @param data
	 * @return String updated JSON to be saved back in siem_overview_data
	 * @throws GeneralException
	 */
	private String updateApplicationCount(SIEMAlertDTO data) throws GeneralException {
		
		log.trace("Entering updateApplicationCount...");
		
		List<AlertDataDTO> applicationCount;
		String applicationName = data.getSourceApplication();
		String typeTotalsJson;
		
		Gson gson = new Gson();
		Type type = new TypeToken<List<AlertDataDTO>>() {}.getType();
		applicationCount = getAlertOverviewData(SIEMConstants.DB_APPLICATION_COUNT);
		
		SIEMUtil.updateTotal(applicationCount, applicationName);
		Collections.sort(applicationCount, AlertDataDTO.countComparator);
		typeTotalsJson = gson.toJson(applicationCount, type);
		
		log.trace("Exiting updateApplicationCount...");
		return typeTotalsJson;
	}
}
