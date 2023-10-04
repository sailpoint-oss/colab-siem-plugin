package com.sailpoint.siem.object;

import java.util.List;

import com.google.gson.Gson;

import sailpoint.object.SyslogEvent;

/**
 * @author prashant.kagwad
 * 
 *         SyslogEventsResponseDTO class (data for syslog event endpoint).
 */
public class SyslogEventsResponseDTO extends EventResponseDTO {
	
	List<SyslogEvent> syslogEvents;
	
	public SyslogEventsResponseDTO() {
		
		super();
	}
	
	public SyslogEventsResponseDTO(int itemsPerPage, int startIndex, int totalResults) {
		
		super(itemsPerPage, startIndex, totalResults);
	}
	
	public SyslogEventsResponseDTO(int itemsPerPage, int startIndex, int totalResults, List<SyslogEvent> syslogEvents) {
		
		super(itemsPerPage, startIndex, totalResults);
		this.syslogEvents = syslogEvents;
	}
	
	public List<SyslogEvent> getSyslogEvents() {
		
		return syslogEvents;
	}
	
	public void setSyslogEvents(List<SyslogEvent> syslogEvents) {
		
		this.syslogEvents = syslogEvents;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
