package com.sailpoint.siem.object;

import com.google.gson.Gson;

/**
 * @author adam.creaney (Created on 12/19/18).
 *
 *         Class to house Identity Link object.
 */
public class IdentityLinkDTO {
	
	private String	linkNativeIdentity;
	private String	linkIdentityId;
	private String	linkApplicationId;
	private String	linkModified;
	private String	linkCreated;
	
	public IdentityLinkDTO() {
		
		super();
	}
	
	public IdentityLinkDTO(String nativeIdentity, String identityId, String applicationId, String modified,
			String created) {
		
		this.linkNativeIdentity = nativeIdentity;
		this.linkIdentityId = identityId;
		this.linkApplicationId = applicationId;
		this.linkModified = modified;
		this.linkCreated = created;
	}
	
	public void setNativeIdentity(String nativeIdentity) {
		
		this.linkNativeIdentity = nativeIdentity;
	}
	
	public String getNativeIdentity() {
		
		return linkNativeIdentity;
	}
	
	public void setIdentityId(String identityId) {
		
		this.linkIdentityId = identityId;
	}
	
	public String getIdentityId() {
		
		return linkIdentityId;
	}
	
	public void setApplicationId(String applicationId) {
		
		this.linkApplicationId = applicationId;
	}
	
	public String getApplicationId() {
		
		return linkApplicationId;
	}
	
	public void setModified(String modified) {
		
		this.linkModified = modified;
	}
	
	public String getModified() {
		
		return linkModified;
	}
	
	public void setCreated(String created) {
		
		this.linkCreated = created;
	}
	
	public String getCreated() {
		
		return linkCreated;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
