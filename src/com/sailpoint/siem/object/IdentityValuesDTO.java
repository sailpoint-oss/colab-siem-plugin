package com.sailpoint.siem.object;

import java.util.Comparator;

import com.google.gson.Gson;

/**
 * @author adam.creaney
 * 
 *         IdentityValuesDTO class.
 */
public class IdentityValuesDTO {
	
	private int		count;
	private String	identityName;
	
	public IdentityValuesDTO() {
		
		super();
	}
	
	public IdentityValuesDTO(int count, String identityName) {
		
		this.count = count;
		this.identityName = identityName;
	}
	
	public int getCount() {
		
		return this.count;
	}
	
	public void setCount(int count) {
		
		this.count = count;
	}
	
	public String getIdentityName() {
		
		return this.identityName;
	}
	
	public void setIdentityName(String identityName) {
		
		this.identityName = identityName;
	}
	
	public static Comparator<IdentityValuesDTO> countComparator = new Comparator<IdentityValuesDTO>() {
		
		@Override
		
		public int compare(IdentityValuesDTO o1, IdentityValuesDTO o2) {
			
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
