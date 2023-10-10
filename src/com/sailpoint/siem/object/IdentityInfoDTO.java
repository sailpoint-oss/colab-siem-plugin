package com.sailpoint.siem.object;

import java.util.List;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

/**
 * @author adam.creaney (Created on 12/17/18).
 *
 *         Class to house Identity Info object.
 */
public class IdentityInfoDTO {
	
	public static class NativeIdentity {
		
		@SerializedName(value = "nativeIdentity")
		private String			nativeIdentity;
		
		@SerializedName(value = "results")
		private List<Identity>	results;
		
		public NativeIdentity() {
			
			super();
		}
		
		public NativeIdentity(String nativeIdentity, List<Identity> results) {
			
			this.nativeIdentity = nativeIdentity;
			this.results = results;
		}
		
		public String getNativeIdentity() {
			
			return nativeIdentity;
		}
		
		public void setNativeIdentity(String nativeIdentity) {
			
			this.nativeIdentity = nativeIdentity;
		}
		
		public List<Identity> getResults() {
			
			return results;
		}
		
		public void setResults(List<Identity> results) {
			
			this.results = results;
		}
		
	}
	
	public static class Identity {
		
		@SerializedName(value = "name")
		private String	name;
		
		@SerializedName(value = "confidence")
		private double	confidence;
		
		public Identity() {
			
			super();
		}
		
		public Identity(String name, double confidence) {
			
			this.name = name;
			this.confidence = confidence;
		}
		
		public String getName() {
			
			return name;
		}
		
		public void setName(String name) {
			
			this.name = name;
		}
		
		public double getConfidence() {
			
			return confidence;
		}
		
		public void setConfidence(double confidence) {
			
			this.confidence = confidence;
		}
		
	}
	
	@SerializedName(value = "identities")
	private List<NativeIdentity> identities;
	
	public IdentityInfoDTO() {
		
		super();
	}
	
	public IdentityInfoDTO(List<NativeIdentity> identities) {
		
		this.identities = identities;
	}
	
	public List<NativeIdentity> getIdentities() {
		
		return identities;
	}
	
	public void setIdentities(List<NativeIdentity> identities) {
		
		this.identities = identities;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
