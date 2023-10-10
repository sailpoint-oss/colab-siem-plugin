package com.sailpoint.siem.object;

import java.util.Date;

import com.google.gson.Gson;

/**
 * @author prashant.kagwad
 * 
 *         AuditEventDTO class ( data for audit event endpoint). Note :
 *         Variables naming convention is changed to match the documentation.
 */
public class AuditEventDTO {
	
	private String	id;
	private Date	created;
	private String	owner;
	// @JsonProperty("interface")
	private String	Interface;
	private String	source;
	private String	action;
	private String	target;
	private String	application;
	// @JsonProperty("account_name")
	private String	accountName;
	private String	instance;
	// @JsonProperty("attribute_name")
	private String	attributeName;
	// @JsonProperty("attribute_value")
	private String	attributeValue;
	// @JsonProperty("tracking_id")
	private String	trackingId;
	private String	attributes;
	private String	string1;
	private String	string2;
	private String	string3;
	private String	string4;
	
	public AuditEventDTO() {
		
		super();
	}
	
	public String getId() {
		
		return id;
	}
	
	public void setId(String id) {
		
		this.id = id;
	}
	
	public Date getCreated() {
		
		return created;
	}
	
	public void setCreated(Date auditEvent) {
		
		this.created = auditEvent;
	}
	
	public String getOwner() {
		
		return owner;
	}
	
	public void setOwner(String owner) {
		
		this.owner = owner;
	}
	
	public String getInterface() {
		
		return Interface;
	}
	
	public void setInterface(String Interface) {
		
		this.Interface = Interface;
	}
	
	public String getSource() {
		
		return source;
	}
	
	public void setSource(String source) {
		
		this.source = source;
	}
	
	public String getAction() {
		
		return action;
	}
	
	public void setAction(String action) {
		
		this.action = action;
	}
	
	public String getTarget() {
		
		return target;
	}
	
	public void setTarget(String target) {
		
		this.target = target;
	}
	
	public String getApplication() {
		
		return application;
	}
	
	public void setApplication(String application) {
		
		this.application = application;
	}
	
	public String getAccountName() {
		
		return accountName;
	}
	
	public void setAccountName(String accountName) {
		
		this.accountName = accountName;
	}
	
	public String getInstance() {
		
		return instance;
	}
	
	public void setInstance(String instance) {
		
		this.instance = instance;
	}
	
	public String getAttributeName() {
		
		return attributeName;
	}
	
	public void setAttributeName(String attributeName) {
		
		this.attributeName = attributeName;
	}
	
	public String getAttributeValue() {
		
		return attributeValue;
	}
	
	public void setAttributeValue(String attributeValue) {
		
		this.attributeValue = attributeValue;
	}
	
	public String getTrackingId() {
		
		return trackingId;
	}
	
	public void setTrackingId(String trackingId) {
		
		this.trackingId = trackingId;
	}
	
	public String getAttributes() {
		
		return attributes;
	}
	
	public void setAttributes(String attributes) {
		
		this.attributes = attributes;
	}
	
	public String getString1() {
		
		return string1;
	}
	
	public void setString1(String string1) {
		
		this.string1 = string1;
	}
	
	public String getString2() {
		
		return string2;
	}
	
	public void setString2(String string2) {
		
		this.string2 = string2;
	}
	
	public String getString3() {
		
		return string3;
	}
	
	public void setString3(String string3) {
		
		this.string3 = string3;
	}
	
	public String getString4() {
		
		return string4;
	}
	
	public void setString4(String string4) {
		
		this.string4 = string4;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
