package com.sailpoint.siem.object;

import java.util.Comparator;

import com.google.gson.Gson;

/**
 * @author adam.creaney
 * 
 *         AlertDataDTO class.
 */
public class AlertDataDTO {
	
	private String	displayName;
	private int		count;
	
	public AlertDataDTO() {
		
		super();
	}
	
	public AlertDataDTO(String displayName, int count) {
		
		this.displayName = displayName;
		this.count = count;
	}
	
	public String getDisplayName() {
		
		return displayName;
	}
	
	public void setDisplayName(String displayName) {
		
		this.displayName = displayName;
	}
	
	public int getCount() {
		
		return count;
	}
	
	public void setCount(int count) {
		
		this.count = count;
	}
	
	public static Comparator<AlertDataDTO> countComparator = new Comparator<AlertDataDTO>() {
		
		@Override
		public int compare(AlertDataDTO o1, AlertDataDTO o2) {
			
			if (o1.getCount() > o2.getCount()) {
				return -1;
			} else if (o1.getCount() < o2.getCount()) {
				return 1;
			} else {
				return 0;
			}
		}
	};
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
