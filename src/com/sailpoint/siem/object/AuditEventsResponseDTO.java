package com.sailpoint.siem.object;

import java.util.List;

import com.google.gson.Gson;

import sailpoint.object.AuditEvent;

/**
 * @author prashant.kagwad
 * 
 *         AuditEventsResponseDTO class (data for audit event endpoint).
 */
public class AuditEventsResponseDTO extends EventResponseDTO {
	
	List<AuditEvent> auditEvents;
	
	public AuditEventsResponseDTO() {
		
		super();
	}
	
	public AuditEventsResponseDTO(int itemsPerPage, int startIndex, int totalResults) {
		
		super(itemsPerPage, startIndex, totalResults);
	}
	
	public AuditEventsResponseDTO(int itemsPerPage, int startIndex, int totalResults, List<AuditEvent> auditEvents) {
		
		super(itemsPerPage, startIndex, totalResults);
		this.auditEvents = auditEvents;
	}
	
	public List<AuditEvent> getAuditEvents() {
		
		return auditEvents;
	}
	
	public void setAuditEvents(List<AuditEvent> auditEvents) {
		
		this.auditEvents = auditEvents;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
