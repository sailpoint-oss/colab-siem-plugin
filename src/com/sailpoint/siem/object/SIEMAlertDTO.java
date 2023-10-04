package com.sailpoint.siem.object;

import com.google.gson.Gson;

/**
 * @author Yogina Patel
 * 
 *         Class containing data for SIEM alert.
 */
public class SIEMAlertDTO {
	
	/**
	 * The id.
	 */
	private String	id;
	
	/**
	 * This is the hibernate id of the Alert in the spt_alert table.
	 */
	private String	alertId;
	
	/**
	 * The created timestamp.
	 */
	private long	created;
	
	/**
	 * The native account name in the end system where alert was triggered
	 */
	private String	nativeId;
	
	/**
	 * The name of the application that triggered the SIEM alert � this should
	 * correspond with the application name in IdentityIQ
	 */
	private String	sourceApplication;
	
	/**
	 * ManagedAttribute name provided by the alert
	 */
	private String	targetGroupName;
	
	/**
	 * ManagedAttribute type provided by the alert
	 */
	private String	targetGroupType;
	
	/**
	 * This is the value �High, Medium, or Low� assigned to the alert.
	 */
	private String	level;
	
	/**
	 * The target_id.
	 */
	private String	targetId;
	
	/**
	 * This is the Unix timestamp of when the alert was processed by the SIEM plugin
	 * service.
	 */
	private long	processedDate;
	
	/**
	 * This is the end-point that created the alert.
	 */
	private String	alertType;
	
	/**
	 * The required action of the alert
	 */
	private String	action;
	
	/**
	 * Alert specific provisioning override
	 */
	private boolean	isOverride;
	
	/**
	 * gets the targetGroupName
	 */
	public String getTargetGroupName() {
		
		return targetGroupName;
	}
	
	/**
	 * sets the targetGroupName
	 */
	public void setTargetGroupName(String targetGroupName) {
		
		this.targetGroupName = targetGroupName;
	}
	
	/**
	 * gets the targetGroupType
	 */
	public String getTargetGroupType() {
		
		return targetGroupType;
	}
	
	/**
	 * sets the targetGroupType
	 */
	public void setTargetGroupType(String targetGroupType) {
		
		this.targetGroupType = targetGroupType;
	}
	
	/**
	 * Gets the id.
	 *
	 * @return The id.
	 */
	public String getId() {
		
		return id;
	}
	
	/**
	 * Sets the id.
	 *
	 * @param id
	 *            The id.
	 */
	public void setId(String id) {
		
		this.id = id;
	}
	
	/**
	 * Gets the alert id.
	 *
	 * @return The alert id.
	 */
	public String getAlertId() {
		
		return alertId;
	}
	
	/**
	 * Sets the alert id.
	 *
	 * @param alertId
	 *            The alert id.
	 */
	public void setAlertId(String alertId) {
		
		this.alertId = alertId;
	}
	
	/**
	 * Gets the created timestamp.
	 *
	 * @return The timestamp.
	 */
	public long getCreated() {
		
		return created;
	}
	
	/**
	 * Sets the created timestamp.
	 *
	 * @param created
	 *            The timestamp.
	 */
	public void setCreated(long created) {
		
		this.created = created;
	}
	
	/**
	 * Gets the level.
	 *
	 * @return The level.
	 */
	public String getLevel() {
		
		return level;
	}
	
	/**
	 * Sets the level.
	 *
	 * @param level
	 *            The level.
	 */
	public void setLevel(String level) {
		
		this.level = level;
	}
	
	/**
	 * Gets the nativeId.
	 *
	 * @return The nativeId.
	 */
	public String getNativeId() {
		
		return nativeId;
	}
	
	/**
	 * Sets the native id.
	 *
	 * @param nativeId
	 *            The native id.
	 */
	public void setNativeId(String nativeId) {
		
		this.nativeId = nativeId;
	}
	
	/**
	 * Gets the source application.
	 *
	 * @return The source application.
	 */
	public String getSourceApplication() {
		
		return sourceApplication;
	}
	
	/**
	 * Sets the source application.
	 *
	 * @param sourceApplication
	 *            The sourceApplication.
	 */
	public void setSourceApplication(String sourceApplication) {
		
		this.sourceApplication = sourceApplication;
	}
	
	/**
	 * Gets the targetId.
	 *
	 * @return The targetId.
	 */
	public String getTargetId() {
		
		return targetId;
	}
	
	/**
	 * Sets the targetId.
	 *
	 * @param targetId
	 *            The targetId.
	 */
	public void setTargetId(String targetId) {
		
		this.targetId = targetId;
	}
	
	/**
	 * Gets the alertType.
	 *
	 * @return The alertType.
	 */
	public String getAlertType() {
		
		return alertType;
	}
	
	/**
	 * Sets the alertType.
	 *
	 * @param alertType
	 *            The alertType.
	 */
	public void setAlertType(String alertType) {
		
		this.alertType = alertType;
	}
	
	/**
	 * Determines if the todo has been processed.
	 *
	 * @return True if processed, false otherwise.
	 */
	public boolean isProcessed() {
		
		return false; // TODO - check if the processedDate has been set;
	}
	
	/**
	 * gets the processedDate.
	 *
	 * @return processedDate.
	 */
	public long getProcessedDate() {
		
		return processedDate;
	}
	
	/**
	 * Sets the processedDate.
	 *
	 * @param processedDate
	 *            .
	 */
	public void setProcessedDate(long processedDate) {
		
		this.processedDate = processedDate;
	}
	
	/**
	 * Gets the desired action
	 *
	 * @return the action
	 */
	public String getAction() {
		
		return action;
	}
	
	/**
	 * Sets the alert action
	 *
	 * @param action
	 *            the action
	 */
	public void setAction(String action) {
		
		this.action = action;
	}
	
	/**
	 * Gets the provisioning type of this alert
	 *
	 * @return
	 */
	public boolean isOverride() {
		
		return isOverride;
	}
	
	/**
	 * Sets the provisioning type (direct/workflow)
	 * 
	 * @param provisionType
	 */
	public void setIsOverride(boolean provisionType) {
		
		this.isOverride = provisionType;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
