package com.sailpoint.siem.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sailpoint.siem.object.AppValuesDTO;
import com.sailpoint.siem.object.IdentityValuesDTO;
import com.sailpoint.siem.object.SIEMAlertDTO;
import com.sailpoint.siem.object.SIEMConstants;
import com.sailpoint.siem.util.SIEMUtil;

import sailpoint.api.SailPointContext;
import sailpoint.api.SailPointFactory;
import sailpoint.object.Alert;
import sailpoint.object.Filter;
import sailpoint.object.Identity;
import sailpoint.object.QueryOptions;
import sailpoint.plugin.PluginBaseHelper;
import sailpoint.plugin.PluginContext;
import sailpoint.tools.GeneralException;
import com.sailpoint.iplus.DBUtils;

/**
 * @author adam.creaney
 * 
 *         SIEMAccess class.
 */
public class SIEMAccess {
	
	private static Log		log	= LogFactory.getLog(SIEMAccess.class);
	
	/**
	 * The plugin context
	 */
	private PluginContext	pluginContext;
	
	/**
	 * Default constructor
	 */
	public SIEMAccess(PluginContext pluginContext) {
		
		this.pluginContext = pluginContext;
	}
	
	/**
	 * Function to get app values from result.
	 * 
	 * @param count
	 * @param appName
	 * @return
	 */
	private AppValuesDTO appValuesFromResult(int count, String appName) {
		
		log.trace("Entering appValuesFromResult...");
		
		AppValuesDTO appValues = new AppValuesDTO();
		appValues.setCount(count);
		appValues.setAppName(appName);
		
		log.trace("Exiting appValuesFromResult...");
		return appValues;
	}
	
	/**
	 * Function to get identity values from results.
	 * 
	 * @param count
	 * @param identityName
	 * @return
	 */
	private IdentityValuesDTO identityValuesFromResult(int count, String identityName) {
		
		log.trace("Entering identityValuesFromResult...");
		
		IdentityValuesDTO identityValues = new IdentityValuesDTO();
		identityValues.setCount(count);
		identityValues.setIdentityName(identityName);
		
		log.trace("Exiting identityValuesFromResult...");
		return identityValues;
	}
	
	/**
	 * Function to get alerts by date.
	 * 
	 * @param timeInterval
	 * @param isDays
	 * @return
	 * @throws GeneralException
	 */
	public List<AppValuesDTO> getAlertsByDate(int timeInterval, boolean isDays) throws GeneralException {
		
		log.trace("Entering getAlertsByDate...");
		
		List<AppValuesDTO> dashboardList = new ArrayList<>();
		int incrementType;
		
		if (isDays) {
			
			incrementType = Calendar.DAY_OF_WEEK;
		} else {
			
			incrementType = Calendar.WEEK_OF_YEAR;
		}
		getAlertCountByDate(timeInterval, dashboardList, incrementType);
		
		log.trace("Exiting getAlertsByDate...");
		return dashboardList;
	}
	
	/**
	 * Function to get count of alerts for specific data range.
	 * 
	 * @param timeInterval
	 * @param dashboardList
	 * @param incrementType
	 * @throws GeneralException
	 */
	private void getAlertCountByDate(int timeInterval, List<AppValuesDTO> dashboardList, int incrementType)
			throws GeneralException {
		
		log.trace("Entering getAlertCountByDate...");
		
		Calendar startDate = Calendar.getInstance();
		startDate.set(Calendar.HOUR_OF_DAY, 0);
		startDate.set(Calendar.MINUTE, 0);
		startDate.set(Calendar.SECOND, 0);
		startDate.set(Calendar.MILLISECOND, 0);
		
		Calendar endDate = Calendar.getInstance();
		endDate.set(Calendar.HOUR_OF_DAY, 0);
		endDate.set(Calendar.MINUTE, 0);
		endDate.set(Calendar.SECOND, 0);
		endDate.set(Calendar.MILLISECOND, 0);
		
		startDate.add(incrementType, 0 - timeInterval);
		endDate.add(incrementType, 0 - (timeInterval - 1));
		
		Format format = new SimpleDateFormat(SIEMConstants.DATE_FORMAT);
		
		for (int i = timeInterval; i >= 0; i--) {
			
			String chartDate = format.format(startDate.getTime());
			log.debug("BETWEEN " + startDate.getTime() + " AND " + endDate.getTime());
			
			SailPointContext sailPointContext = SailPointFactory.getCurrentContext();
			List<Filter> filterList = new ArrayList<>();
			
			Filter typeFilter = Filter.eq(SIEMConstants.FILTER_TYPE, SIEMConstants.SIEM_ALERT);
			filterList.add(typeFilter);
			
			Filter startDateFilter = Filter.ge(SIEMConstants.FILTER_CREATED, startDate.getTime());
			filterList.add(startDateFilter);
			
			Filter endDateFilter = Filter.lt(SIEMConstants.FILTER_CREATED, endDate.getTime());
			filterList.add(endDateFilter);
			
			Filter filter = Filter.and(filterList);
			
			QueryOptions qo = new QueryOptions();
			qo.add(filter);
			int alertCount = sailPointContext.countObjects(Alert.class, qo);
			
			dashboardList.add(appValuesFromResult(alertCount, chartDate));
			
			startDate.add(incrementType, 1);
			endDate.add(incrementType, 1);
		}
		
		log.trace("Entering getAlertCountByDate...");
	}
	
	/**
	 * Function to get alerts based on the type of alert.
	 * 
	 * @param alertType
	 * @return
	 * @throws GeneralException
	 */
	public List<SIEMAlertDTO> getAlertType(String alertType) throws GeneralException {
		
		log.trace("Entering getAlertType");
		
		List<SIEMAlertDTO> alertList = new ArrayList<>();
		
		Date date = new Date();
		long currentUnixTime = date.getTime();
		long twentyFourHoursInMs = 24 * 60 * 60 * 1000;
		long alertsSinceUnixTime = currentUnixTime - twentyFourHoursInMs;
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.GET_ALERT_TYPE, alertType,
					alertsSinceUnixTime);
			
			log.debug("statement : " + statement);
			ResultSet resultSet = statement.executeQuery();
			while (resultSet.next()) {
				
				SIEMAlertDTO siemAlert = SIEMUtil.alertFromResultSet(resultSet);
				alertList.add(siemAlert);
			}
		} catch (SQLException e) {
			
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				e.printStackTrace();
			}
		}
		
		log.trace("Leaving getAlertType");
		return alertList;
	}
	
	/**
	 * Function to fetch identities.
	 * 
	 * @param limit
	 * @return
	 * @throws GeneralException
	 */
	public List<IdentityValuesDTO> getIdentities(int limit) throws GeneralException {
		
		log.trace("Entering getIdentities...");
		
		SailPointContext sailPointContext = SailPointFactory.getCurrentContext();
		
		List<IdentityValuesDTO> identityCountList = new ArrayList<>();
		List<String> countedIdList = new ArrayList<String>();
		
		Filter typeFilter = Filter.eq(SIEMConstants.FILTER_TYPE, SIEMConstants.SIEM_ALERT);
		Filter targetIdNotNullFilter = Filter.notnull(SIEMConstants.FILTER_TARGET_ID);
		
		QueryOptions qo = new QueryOptions();
		qo.add(typeFilter, targetIdNotNullFilter);
		qo.setDistinct(true);
		Iterator<?> identityIdIterator = sailPointContext.search(Alert.class, qo, SIEMConstants.SCORE_TARGET_ID);
		
		// TODO: optimize this for performance, move processing to DB
		if (identityIdIterator != null) {
			
			// iterate through all all identityIds from alert table
			while (identityIdIterator.hasNext()) {
				
				Object[] identityIdArray = (Object[]) identityIdIterator.next();
				String identityId = (String) identityIdArray[0];
				
				// check if id is null and if we've already counted this identity
				if ((identityId != null) && (!countedIdList.contains(identityId))) {
					
					Filter targetIDFilter = Filter.eq(SIEMConstants.FILTER_TARGET_ID, identityId);
					QueryOptions qo2 = new QueryOptions();
					qo2.add(targetIDFilter, typeFilter);
					
					// count alerts associated with identity
					int identityCount = sailPointContext.countObjects(Alert.class, qo2);
					
					// get identity name and add to the result list
					Identity identity = sailPointContext.getObjectById(Identity.class, identityId);
					if (identity != null) {
						
						String identityName = identity.getName();
						identityCountList.add(identityValuesFromResult(identityCount, identityName));
						countedIdList.add(identityId);
						Collections.sort(identityCountList, IdentityValuesDTO.countComparator);
						
						// trim list if larger than limit
						if (identityCountList.size() > limit) {
							
							identityCountList.remove(limit);
						}
					}
				}
			}
		}
		
		log.trace("Exiting getIdentities...");
		return identityCountList;
	}
}
