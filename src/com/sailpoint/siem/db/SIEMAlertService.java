package com.sailpoint.siem.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sailpoint.siem.object.SIEMAlertDTO;
import com.sailpoint.siem.util.SIEMUtil;

import sailpoint.plugin.PluginBaseHelper;
import sailpoint.plugin.PluginContext;
import sailpoint.tools.GeneralException;
import sailpoint.tools.ObjectNotFoundException;
import sailpoint.tools.Util;
import com.sailpoint.iplus.DBUtils;

/**
 * @author adam.creaney (Created on 4/20/17)
 * 
 *         SIEMAlertService class.
 */
public class SIEMAlertService {
	
	/**
	 * the class logger
	 */
	private static Log		log	= LogFactory.getLog(SIEMAlertService.class);
	
	/**
	 * The plugin context
	 */
	private PluginContext	pluginContext;
	
	/**
	 * Default constructur
	 */
	public SIEMAlertService(PluginContext pluginContext) {
		
		this.pluginContext = pluginContext;
	}
	
	/**
	 * Function to get all new SIEM Alerts.
	 *
	 * @param sort
	 *            Should the list be sorted by priority.
	 * @return SIEM Alerts
	 * @throws GeneralException
	 */
	public List<SIEMAlertDTO> getNewAlerts(boolean sort) throws GeneralException {
		
		log.trace("Entering getNewAlerts...");
		
		List<SIEMAlertDTO> alerts = new ArrayList<SIEMAlertDTO>();
		Connection connection = null;
		PreparedStatement statement = null;
		try {
			
			connection = pluginContext.getConnection();
			if (sort) {
				
				statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.NEW_ALERTS_SORTED);
			} else {
				
				statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.NEW_ALERTS);
				
			}
			
			ResultSet rs = statement.executeQuery();
			while (rs.next()) {
				
				alerts.add(SIEMUtil.alertFromResultSet(rs));
			}
			
			if (sort) {
				
				log.debug("sort setting is true.");
				alerts = SIEMUtil.sortAlerts(alerts);
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
		
		log.trace("Exiting getNewAlerts...");
		return alerts;
	}
	
	/**
	 * Function to return all open alerts in the plugin database.
	 *
	 * @param sort
	 *            specifies whether alert list should be returned sorted
	 * @return
	 * @throws GeneralException
	 */
	public List<SIEMAlertDTO> getOpenAlerts(boolean sort) throws GeneralException {
		
		log.trace("Entering getOpenAlerts");
		
		List<SIEMAlertDTO> alerts = new ArrayList<SIEMAlertDTO>();
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			connection = pluginContext.getConnection();
			if (sort) {
				
				statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.OPEN_ALERTS_SORTED);
			} else {
				
				statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.OPEN_ALERTS);
			}
			
			ResultSet rs = statement.executeQuery();
			while (rs.next()) {
				
				alerts.add(SIEMUtil.alertFromResultSet(rs));
			}
			
			if (sort) {
				
				log.debug("sort setting is true.");
				alerts = SIEMUtil.sortAlerts(alerts);
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
		
		log.trace("Exiting getOpenAlerts");
		return alerts;
	}
	
	/**
	 * Function to return a list of Alerts that are older than a provided date.
	 *
	 * @param date
	 *            cutoff date used to define 'old'
	 * @param sort
	 *            result should be sorted by level
	 * @return alerts List of alerts older than provided date
	 * @throws GeneralException
	 */
	public List<SIEMAlertDTO> getOldAlerts(long date, boolean sort) throws GeneralException {
		
		log.trace("Entering getOldAlerts...");
		
		List<SIEMAlertDTO> alerts = new ArrayList<SIEMAlertDTO>();
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			connection = pluginContext.getConnection();
			if (sort) {
				
				statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.OLD_ALERTS_SORTED, date);
			} else {
				
				statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.OLD_ALERTS, date);
			}
			
			ResultSet rs = statement.executeQuery();
			while (rs.next()) {
				
				alerts.add(SIEMUtil.alertFromResultSet(rs));
			}
			
			if (sort) {
				
				log.debug("sort setting is true.");
				alerts = SIEMUtil.sortAlerts(alerts);
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
		
		log.trace("Exiting getOldAlerts");
		return alerts;
	}
	
	/**
	 * Function to update an alert in the plugin table with the sailpoing object id
	 * of the Alert in IIQ.
	 *
	 * @param id
	 *            the plugin table id.
	 * @param alertId
	 *            the SailPoint object id.
	 */
	public void updateAlertId(String id, String alertId) throws GeneralException {
		
		log.trace("Entering updateAlertId...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.UPDATE_ALERT_ID, alertId, id);
			statement.executeUpdate();
			
		} catch (SQLException e) {
			
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				e.printStackTrace();
			}
		}
		
		log.trace("Exiting updateAlertId...");
	}
	
	/**
	 * Function to update an alert with a processed date.
	 *
	 * @param id
	 * @param processedDate
	 * @throws GeneralException
	 */
	public void updateAlertProcessed(String id, long processedDate) throws GeneralException {
		
		log.trace("Entering updateAlertProcessed...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.UPDATE_ALERT_PROCESSED,
					processedDate, id);
			statement.executeUpdate();
			
		} catch (SQLException e) {
			
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				e.printStackTrace();
			}
		}
		
		log.trace("Exiting updateAlertProcessed...");
	}
	
	/**
	 * Function to create a new SIEMAlert with the specified data.
	 *
	 * @param data
	 *            The alert data.
	 * @return The SIEMAlert.
	 * @throws GeneralException
	 */
	public SIEMAlertDTO createSIEMAlert(SIEMAlertDTO data) throws GeneralException {
		
		log.trace("Entering createSIEMAlert()");
		
		Connection connection = null;
		PreparedStatement statement = null;
		String autoId = "";
		
		try {
			
			data.setId(Util.uuid());
			connection = pluginContext.getConnection();
			statement = connection.prepareStatement(DBQueryStatements.ADD);
			
			statement.setString(1, data.getId());
			statement.setLong(2, data.getCreated());
			statement.setString(3, data.getNativeId());
			statement.setString(4, data.getSourceApplication());
			statement.setString(5, data.getTargetGroupName());
			statement.setString(6, data.getTargetGroupType());
			statement.setString(7, data.getLevel());
			statement.setString(8, data.getAlertType());
			statement.setString(9, data.getAction());
			statement.setBoolean(10, data.isOverride());
			statement.executeUpdate();
			
			// ResultSet rs = statement.getGeneratedKeys();
			// rs.next();
			autoId = data.getId();
			
		} catch (SQLException e) {
			
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				e.printStackTrace();
			}
		}
		
		log.trace("Exiting createSIEMAlert...");
		return getSIEMAlert(autoId);
	}
	
	/**
	 * Function to delete an alert entry from the plugin table.
	 *
	 * @param id
	 *            the ID of the entry to delete.
	 * @throws GeneralException
	 */
	public void deleteAlert(String id) throws GeneralException {
		
		log.trace("Entering deleteAlert...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.DELETE_ALERT, id);
			statement.executeUpdate();
			
		} catch (SQLException e) {
			
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				e.printStackTrace();
			}
		}
		
		log.trace("Exiting deleteAlert...");
	}
	
	/**
	 * Function to delete all alert of specified level.
	 *
	 * @param level
	 *            The level.
	 * @throws GeneralException
	 */
	public void deleteAlertsByLevel(String level) throws GeneralException {
		
		log.trace("Entering deleteAlertsByLevel...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			
			connection = pluginContext.getConnection();
			
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.DELETE_BY_LEVEL, level);
			statement.executeUpdate();
		} catch (SQLException e) {
			
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				e.printStackTrace();
			}
		}
		
		log.trace("Exiting deleteAlertsByLevel...");
	}
	
	/**
	 * Function to delete all alert processed before specified date.
	 *
	 * @param processedDate
	 *            The processed date.
	 * @throws GeneralException
	 */
	public void deleteAlertsByDate(long processedDate) throws GeneralException {
		
		log.trace("Entering deleteAlertsByDate...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.DELETE_BEFORE_DATE,
					processedDate);
			statement.executeUpdate();
		} catch (SQLException e) {
			
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				e.printStackTrace();
			}
		}
		
		log.trace("Exiting deleteAlertsByDate...");
	}
	
	/**
	 * Function to delete all alerts in the system.
	 *
	 * @throws GeneralException
	 */
	public void deleteAllAlerts() throws GeneralException {
		
		log.trace("Entering deleteAlertsByDate...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.DELETE_ALL);
			statement.executeUpdate();
		} catch (SQLException e) {
			
			throw new GeneralException(e);
		} finally {
			
			try {
				
				DBUtils.closeDBObjects(connection, statement);
			} catch (SQLException e) {
				
				e.printStackTrace();
			}
		}
		
		log.trace("Exiting deleteAlertsByDate...");
	}
	
	/**
	 * Function to get the specified alert.
	 *
	 * @param id
	 *            The alert id.
	 * @return The SIEMAlert.
	 * @throws GeneralException
	 */
	public SIEMAlertDTO getSIEMAlert(String id) throws GeneralException {
		
		log.trace("Entering getSIEMAlert...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		SIEMAlertDTO alert = null;
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.GET_ALERT_BY_ID, id);
			ResultSet resultSet = statement.executeQuery();
			
			if (resultSet.next()) {
				
				alert = SIEMUtil.alertFromResultSet(resultSet);
			} else {
				
				throw new ObjectNotFoundException();
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
		
		log.trace("Existing getSIEMAlert...");
		return alert;
	}
	
	/**
	 * Function to get all alerts of specified level.
	 *
	 * @param level
	 *            The user id.
	 * @return The alerts.
	 * @throws GeneralException
	 */
	public List<SIEMAlertDTO> getSIEMAlertsByLevel(String level) throws GeneralException {
		
		log.trace("Entering getSIEMAlertsByLevel...");
		
		Connection connection = null;
		PreparedStatement statement = null;
		
		List<SIEMAlertDTO> alerts = new ArrayList<>();
		
		try {
			
			connection = pluginContext.getConnection();
			statement = PluginBaseHelper.prepareStatement(connection, DBQueryStatements.ALERTS_BY_LEVEL, level);
			ResultSet resultSet = statement.executeQuery();
			
			while (resultSet.next()) {
				
				alerts.add(SIEMUtil.alertFromResultSet(resultSet));
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
		
		log.trace("Existing getSIEMAlertsByLevel...");
		return alerts;
	}
}
