package com.sailpoint.siem.object;

import com.google.gson.Gson;

public class ErrorResponseDTO {
	
	private String	code;
	private String	message;
	private String	details;
	
	public ErrorResponseDTO() {
		
		super();
	}
	
	public ErrorResponseDTO(String code, String message, String details) {
		
		super();
		this.code = code;
		this.message = message;
		this.details = details;
	}
	
	public String getCode() {
		
		return code;
	}
	
	public void setCode(String code) {
		
		this.code = code;
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
