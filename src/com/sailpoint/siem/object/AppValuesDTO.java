package com.sailpoint.siem.object;

import com.google.gson.Gson;

/**
 * @author adam.creaney
 * 
 *         AppValuesDTO class.
 */
public class AppValuesDTO {
	
	private int		count;
	private String	appName;
	
	public AppValuesDTO() {
		
		super();
	}
	
	public AppValuesDTO(int count, String appName) {
		
		this.count = count;
		this.appName = appName;
	}
	
	public int getCount() {
		
		return this.count;
	}
	
	public void setCount(int count) {
		
		this.count = count;
	}
	
	public String getAppName() {
		
		return this.appName;
	}
	
	public void setAppName(String appName) {
		
		this.appName = appName;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
