package com.sailpoint.siem.db;

/**
 * @author adam.creaney (Created on 4/17/17)
 * 
 *         Query statement class for all database related operations.
 */
public class DBQueryStatements {
	
	/**
	 * Private constructor.
	 */
	private DBQueryStatements() {}
	
	/**
	 * Get all new SIEMAlerts
	 */
	public static final String	NEW_ALERTS				= "SELECT * FROM siem_alert WHERE alert_id IS NULL AND processed_date IS NULL";
	
	/**
	 * Get all new SIEMAlerts in priority alert_level
	 */
	public static final String	NEW_ALERTS_SORTED		= "SELECT * FROM siem_alert WHERE alert_id IS NULL AND processed_date IS NULL ORDER BY CASE alert_level "
			+ "WHEN 'high' THEN 1 " + "WHEN 'medium' THEN 2 " + "WHEN 'low' THEN 3 " + "END";
	
	/**
	 * Get all the open SIEMAlerts
	 */
	public static final String	OPEN_ALERTS				= "SELECT * FROM siem_alert WHERE alert_id IS NOT NULL AND processed_date IS NULL";
	
	/**
	 * Get all open SIEMAlerts in priority alert_level
	 */
	public static final String	OPEN_ALERTS_SORTED		= "SELECT * FROM siem_alert WHERE alert_id IS NOT NULL AND processed_date IS NULL ORDER BY CASE alert_level "
			+ "WHEN 'high' THEN 1 " + "WHEN 'medium' THEN 2 " + "WHEN 'low' THEN 3 " + "END";
	
	/**
	 * Update plugin alert entry with processed date
	 */
	public static final String	UPDATE_ALERT_PROCESSED	= "UPDATE siem_alert SET processed_date=? WHERE id=?";
	
	/**
	 * Update plugin alert entry with IdentityIQ object id
	 */
	public static final String	UPDATE_ALERT_ID			= "UPDATE siem_alert SET alert_id=? WHERE id=?";
	
	/**
	 * Get all alerts older than prune date
	 */
	public static final String	OLD_ALERTS				= "SELECT * FROM siem_alert WHERE created < ?";
	
	/**
	 * Get all alerts older than prune date in sorted order
	 */
	public static final String	OLD_ALERTS_SORTED		= "SELECT * FROM siem_alert WHERE created < ? ORDER BY CASE alert_level "
			+ "WHEN 'high' THEN 1 " + "WHEN 'medium' THEN 2 " + "WHEN 'low' THEN 3 " + "END";
	
	/**
	 * Delete and alert by 'id'
	 */
	public static final String	DELETE_ALERT			= "DELETE FROM siem_alert WHERE id=?";
	
	/**
	 * Query to get all alerts by alert_level.
	 */
	public static final String	ALERTS_BY_LEVEL			= "SELECT * FROM siem_alert WHERE alert_level=? ORDER BY processed_date ASC";
	
	/**
	 * Query to select a single alert by id.
	 */
	public static final String	GET_ALERT_BY_ID			= "SELECT * FROM siem_alert WHERE id=?";
	
	/**
	 * Query to add a alert. TODO Question - When should we set the processed_date
	 * field?
	 */
	public static final String	ADD						= "INSERT INTO siem_alert "
			+ "(id, created, native_id, source_application, target_group_name, target_group_type, alert_level, alert_type, action, use_workflow)"
			+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	
	/**
	 * Query to delete all alerts by alert_level.
	 */
	public static final String	DELETE_BY_LEVEL			= "DELETE FROM siem_alert WHERE alert_level=?";
	
	/**
	 * Query to delete all alerts by processed_date.
	 */
	public static final String	DELETE_BEFORE_DATE		= "DELETE FROM siem_alert WHERE processed_date < ?";
	
	/**
	 * Query to delete all alerts in the table.
	 */
	public static final String	DELETE_ALL				= "DELETE FROM siem_alert";
	
	/**
	 * Query to get a specific alert type
	 */
	public static final String	GET_ALERT_TYPE			= "SELECT * FROM siem_alert WHERE alert_type=? AND created>=?";
	
	/**
	 * Query to get data for overview widget
	 *
	 */
	public static final String	GET_OVERVIEW_DATA		= "SELECT * FROM siem_overview_data WHERE id=1";
	
	/**
	 * Query to update siem_overview_data
	 *
	 */
	public static final String	UPDATE_OVERVIEW_DATA	= "UPDATE siem_overview_data SET type_totals=?, account_metrics=?, "
			+ "application_metrics=?, application_count=? WHERE id=1";
}
