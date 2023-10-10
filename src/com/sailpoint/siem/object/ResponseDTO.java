package com.sailpoint.siem.object;

import com.google.gson.Gson;

public class ResponseDTO {
	
	private String	status;
	private String	message;
	private String	details;
	
	public ResponseDTO() {
		
		super();
	}
	
	public ResponseDTO(String status, String message, String details) {
		
		super();
		this.status = status;
		this.message = message;
		this.details = details;
	}
	
	public String getStatus() {
		
		return status;
	}
	
	public void setStatus(String status) {
		
		this.status = status;
	}
	
	public String getMessage() {
		
		return message;
	}
	
	public void setMessage(String message) {
		
		this.message = message;
	}
	
	public String getDetails() {
		
		return details;
	}
	
	public void setDetails(String details) {
		
		this.details = details;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
