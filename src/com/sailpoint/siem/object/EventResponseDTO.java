package com.sailpoint.siem.object;

import com.google.gson.Gson;

public class EventResponseDTO {
	
	private int	itemsPerPage;
	private int	currentIndex;
	private int	totalResults;
	
	public EventResponseDTO() {
		
		super();
	}
	
	public EventResponseDTO(int itemsPerPage, int currentIndex, int totalResults) {
		
		super();
		this.itemsPerPage = itemsPerPage;
		this.currentIndex = currentIndex;
		this.totalResults = totalResults;
	}
	
	public int getItemsPerPage() {
		
		return itemsPerPage;
	}
	
	public void setItemsPerPage(int itemsPerPage) {
		
		this.itemsPerPage = itemsPerPage;
	}
	
	public int getCurrentIndex() {
		
		return currentIndex;
	}
	
	public void setCurrentIndex(int currentIndex) {
		
		this.currentIndex = currentIndex;
	}
	
	public int getTotalResults() {
		
		return totalResults;
	}
	
	public void setTotalResults(int totalResults) {
		
		this.totalResults = totalResults;
	}
	
	public String toString() {
		
		Gson gson = new Gson();
		return gson.toJson(this);
	}
}
