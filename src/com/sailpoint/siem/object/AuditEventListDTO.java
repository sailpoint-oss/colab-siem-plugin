package com.sailpoint.siem.object;

import java.util.List;

import com.google.gson.Gson;

/**
 * @author prashant.kagwad
 * 
 *         AuditEventListDTO class (data for audit event endpoint).
 */
public class AuditEventListDTO {
	
	private int					totalResults;
	private int					itemsPerPage;
	private int					currentIndex;
	
	// @JsonProperty("AuditEvents")
	private List<AuditEventDTO>	auditEvents;
	
	public AuditEventListDTO() {
		
		super();
	}
	
	public AuditEventListDTO(int totalResults, int itemsPerPage, int currentIndex, List<AuditEventDTO> auditEvents) {
		
		this.totalResults = totalResults;
		this.itemsPerPage = itemsPerPage;
		this.currentIndex = currentIndex;
		this.auditEvents = auditEvents;
	}
	
	public int getTotalResults() {
		
		return totalResults;
	}
	
	public void setTotalResults(int totalResults) {
		
		this.totalResults = totalResults;
	}
	
	public int getItemsPerPage() {
		
		return itemsPerPage;
	}
	
	public void setItemsPerPage(int itemsPerPage) {
		
		this.itemsPerPage = itemsPerPage;
	}
	
	public int getCurrentIndex() {
		
		return currentIndex;
	}
	
	public void setCurrentIndex(int currentIndex) {
		
		this.currentIndex = currentIndex;
	}
	
	public List<AuditEventDTO> getAuditEvents() {
		
		return auditEvents;
	}
	
	public void setAuditEvents(List<AuditEventDTO> auditEvents) {
		
		this.auditEvents = auditEvents;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
