package com.sailpoint.siem.object;

import com.google.gson.Gson;

/**
 * @author prashant.kagwad
 * 
 *         AuditActionDTO class (results for auditConfiguration endpoint).
 */
public class AuditActionDTO {
	
	private String	name;
	private boolean	enabled;
	
	public AuditActionDTO() {
		
		super();
	}
	
	public AuditActionDTO(String name, boolean enabled) {
		
		this.name = name;
		this.enabled = enabled;
	}
	
	public String getName() {
		
		return name;
	}
	
	public void setName(String name) {
		
		this.name = name;
	}
	
	public boolean isEnabled() {
		
		return enabled;
	}
	
	public void setEnabled(boolean enabled) {
		
		this.enabled = enabled;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
