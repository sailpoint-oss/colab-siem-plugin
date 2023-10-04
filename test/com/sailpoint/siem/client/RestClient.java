package com.sailpoint.siem.client;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;

public class RestClient {
	
	Client	client			= Client.create();
	String	ip				= "192.168.239.231";
	String	getUrl			= "http://" + ip + ":8080/identityiq/plugin/rest/SIEMPlugin/plainTextHello";
	String	postIdentityUrl	= "http://" + ip + ":8080/identityiq/plugin/rest/SIEMPlugin/identity/";
	String	postAppUrl		= "http://" + ip + ":8080/identityiq/plugin/rest/SIEMPlugin/application/";
	
	public void getRequest() {
		
		client.addFilter(new HTTPBasicAuthFilter("jerry.bennett", "xyzzy"));
		
		WebResource webResource = client.resource(getUrl);
		ClientResponse response = webResource.accept("application/json").get(ClientResponse.class);
		/*
		 * if(response.getStatus()!=200){ throw new RuntimeException("HTTP Error: "+
		 * response.getStatus()); }
		 */
		
		System.out.println("Response: " + response.toString());
		String result = response.getEntity(String.class);
		System.out.println("Response from the Server: " + result);
	}
	
	public void postIdentityAccountRequests() {
		
		// client.addFilter(new HTTPBasicAuthFilter("Adam.Kennedy", "sailpoint")); //
		// Regular user - no spright. Should fail.
		client.addFilter(new HTTPBasicAuthFilter("Jerry.Bennett", "xyzzy")); // System Administrator. Should be allowed.
		// client.addFilter(new HTTPBasicAuthFilter("Aaron.Nichols", "xyzzy")); //
		// SIEMAdministrator right. Should be allowed.
		
		// String disblUsrDN = "CN=Billy
		// Holmes,OU=London,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		String disblUsrDN = "CN=Terry Fisher,OU=Munich,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		WebResource webResource = null;
		String inputData = null;
		ClientResponse response = null;
		String result = null;
		
		/**
		 * Disable Account
		 */
		webResource = client.resource(postIdentityUrl + "account");
		inputData = "{\"application\":\"Active Directory\",\"native_id\":\"" + disblUsrDN
				+ "\",\"action\":\"Disable\",\"level\":\"Medium\",\"date\":\"#\",\"use_workflow\":\"false\"}";
		response = webResource.accept("application/json").type("application/json").post(ClientResponse.class,
				inputData);
		result = response.getEntity(String.class);
		System.out.println("Disable identity/account: " + result);
		
		/**
		 * Delete Account
		 */
		/*
		 * webResource = client.resource(postIdentityUrl + "account"); inputData =
		 * "{\"application\":\"Active Directory\",\"native_id\":\""+deleteUsrDN+
		 * "\",\"action\":\"Delete\",\"level\":\"Medium\",\"date\":\"1495810195000\"}";
		 * response =
		 * webResource.accept("application/json").type("application/json").post(
		 * ClientResponse.class,inputData); result = response.getEntity(String.class);
		 * System.out.println("Delete identity/account: " + result);
		 */
		
	}
	
	public void postIdentityAccountsRequests() {
		
		client.addFilter(new HTTPBasicAuthFilter("spadmin", "admin"));
		
		// String disblUsrDN = "CN=Billy
		// Holmes,OU=London,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		String disblUsrDN = "CN=Terry Fisher,OU=Munich,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		WebResource webResource = null;
		String inputData = null;
		ClientResponse response = null;
		String result = null;
		
		/**
		 * Disable Account
		 */
		webResource = client.resource(postIdentityUrl + "accounts");
		inputData = "{\"application\":\"Active Directory\",\"native_id\":\"" + disblUsrDN
				+ "\",\"action\":\"Disable\",\"level\":\"Medium\",\"date\":\"1495810195000\"}";
		response = webResource.accept("application/json").type("application/json").post(ClientResponse.class,
				inputData);
		result = response.getEntity(String.class);
		System.out.println("Disable identity/accounts: " + result);
		
		/**
		 * Delete Account
		 */
		/*
		 * webResource = client.resource(postIdentityUrl + "accounts"); inputData =
		 * "{\"application\":\"Active Directory\",\"native_id\":\""+deleteUsrDN+
		 * "\",\"action\":\"Delete\",\"level\":\"Medium\",\"date\":\"1495810195000\"}";
		 * response =
		 * webResource.accept("application/json").type("application/json").post(
		 * ClientResponse.class,inputData); result = response.getEntity(String.class);
		 * System.out.println("Delete identity/accounts: " + result);
		 */
	}
	
	public void postIdentityEntitlementRequests() {
		
		client.addFilter(new HTTPBasicAuthFilter("spadmin", "admin"));
		
		String usrDN = "CN=Betty Young,OU=Austin,OU=Americas,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		String grpDN = "CN=Development,OU=Groups,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		// String grpDN = "Dev";
		WebResource webResource = null;
		String inputData = null;
		ClientResponse response = null;
		String result = null;
		
		/**
		 * Single Entitlement, Single App
		 */
		/*
		 * webResource = client.resource(postIdentityUrl + "entitlement"); inputData =
		 * "{\"application\":\"Active Directory\",\"native_id\":\""+usrDN+
		 * "\",\"group_name\":\""+grpDN+
		 * "\",\"group_type\":\"memberOf\",\"level\":\"Medium\",\"date\":\"1495810195000\"}";
		 * response =
		 * webResource.accept("application/json").type("application/json").post(
		 * ClientResponse.class,inputData); result = response.getEntity(String.class);
		 * System.out.println("identity/entitlement: " + result);
		 */
		/**
		 * All Entitlements, Single App
		 */
		/*
		 * String usrDN2 =
		 * "CN=Craig Hart,OU=Singapore,OU=Asia-Pacific,OU=Demo,DC=seri,DC=sailpointdemo,DC=com"
		 * ;
		 * 
		 * webResource = client.resource(postIdentityUrl + "entitlements"); inputData =
		 * "{\"application\":\"Active Directory\",\"native_id\":\""+usrDN2+
		 * "\",\"level\":\"Medium\",\"date\":\"1495810195000\"}"; response =
		 * webResource.accept("application/json").type("application/json").post(
		 * ClientResponse.class,inputData); result = response.getEntity(String.class);
		 * System.out.println("identity/entitlements: " + result);
		 */
		
		/**
		 * All Entitlements, All Apps
		 */
		String usrDN3 = "CN=Edward Baker,OU=Brazil,OU=Americas,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		
		webResource = client.resource(postIdentityUrl + "entitlements-all");
		inputData = "{\"application\":\"Active Directory\",\"native_id\":\"" + usrDN3
				+ "\",\"level\":\"Medium\",\"date\":\"1495810195000\"}";
		response = webResource.accept("application/json").type("application/json").post(ClientResponse.class,
				inputData);
		result = response.getEntity(String.class);
		System.out.println("identity/entitlements-all: " + result);
	}
	
	public void postIdentityPasswordRequests() {
		
		client.addFilter(new HTTPBasicAuthFilter("spadmin", "admin"));
		
		String usrDN = "CN=Joyce Griffin,OU=Brussels,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		WebResource webResource = null;
		String inputData = null;
		ClientResponse response = null;
		String result = null;
		
		/**
		 * Single Password
		 */
		webResource = client.resource(postIdentityUrl + "password");
		inputData = "{\"application\":\"Active Directory\",\"native_id\":\"" + usrDN
				+ "\",\"level\":\"Medium\",\"date\":\"1495677600000\"}";
		response = webResource.accept("application/json").type("application/json").post(ClientResponse.class,
				inputData);
		result = response.getEntity(String.class);
		System.out.println("identity/password: " + result);
		
		/**
		 * All Passwords
		 */
		String usrDN2 = "CN=Juan Hamilton,OU=Brussels,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		
		webResource = client.resource(postIdentityUrl + "passwords");
		inputData = "{\"application\":\"Active Directory\",\"native_id\":\"" + usrDN2
				+ "\",\"level\":\"Medium\",\"date\":\"1495810195000\"}";
		response = webResource.accept("application/json").type("application/json").post(ClientResponse.class,
				inputData);
		result = response.getEntity(String.class);
		System.out.println("identity/passwords: " + result);
		
	}
	
	public void postIdentityCertifyRequests() {
		
		client.addFilter(new HTTPBasicAuthFilter("spadmin", "admin"));
		
		String usrDN = "CN=Joyce Griffin,OU=Brussels,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		WebResource webResource = null;
		String inputData = null;
		ClientResponse response = null;
		String result = null;
		
		/**
		 * Single Application
		 */
		webResource = client.resource(postIdentityUrl + "certify");
		inputData = "{\"application\":\"PRISM\",\"native_id\":\"whenderson\",\"level\":\"Medium\",\"date\":\"1495677600000\"}";
		response = webResource.accept("application/json").type("application/json").post(ClientResponse.class,
				inputData);
		result = response.getEntity(String.class);
		System.out.println("identity/certify: " + result);
		
		/**
		 * All Applications
		 */
		/*
		 * String usrDN2 =
		 * "CN=Juan Hamilton,OU=Brussels,OU=Europe,OU=Demo,DC=seri,DC=sailpointdemo,DC=com"
		 * ;
		 * 
		 * webResource = client.resource(postIdentityUrl + "certify-all"); inputData =
		 * "{\"application\":\"Active Directory\",\"native_id\":\""+usrDN2+
		 * "\",\"level\":\"Medium\",\"date\":\"1495810195000\"}"; response =
		 * webResource.accept("application/json").type("application/json").post(
		 * ClientResponse.class,inputData); result = response.getEntity(String.class);
		 * System.out.println("identity/certify-all: " + result);
		 */
	}
	
	public void postApplicationRequests() {
		
		client.addFilter(new HTTPBasicAuthFilter("spadmin", "admin"));
		
		String grpDN = "CN=PayrollAnalysis,OU=Groups,OU=Demo,DC=seri,DC=sailpointdemo,DC=com";
		WebResource webResource = null;
		String inputData = null;
		ClientResponse response = null;
		String result = null;
		
		/*
		 * webResource = client.resource(postAppUrl + "group"); inputData =
		 * "{\"application\":\"Active Directory\",\"group_type\":\"memberOf\",\"group_name\":\""
		 * +grpDN+
		 * "\",\"level\":\"High\",\"date\":\"1495810195000\",\"use_workflow\":\"false\"}";
		 * response =
		 * webResource.accept("application/json").type("application/json").post(
		 * ClientResponse.class,inputData); result = response.getEntity(String.class);
		 * System.out.println("application/group: " + result);
		 */
		
		webResource = client.resource(postAppUrl + "accounts");
		inputData = "{\"application\":\"PRISM\",\"action\":\"disable\",\"level\":\"High\",\"date\":\"1495677600000\"}";
		response = webResource.accept("application/json").type("application/json").post(ClientResponse.class,
				inputData);
		result = response.getEntity(String.class);
		System.out.println("application/accounts: " + result);
		
		webResource = client.resource(postAppUrl + "certify-group");
		inputData = "{\"application\":\"Active Directory\",\"group_type\":\"memberOf\",\"group_name\":\"" + grpDN
				+ "\",\"level\":\"High\",\"date\":\"1495810195000\",\"use_workflow\":\"false\"}";
		response = webResource.accept("application/json").type("application/json").post(ClientResponse.class,
				inputData);
		result = response.getEntity(String.class);
		System.out.println("application/certify-group: " + result);
		
		/*
		 * webResource = client.resource(postAppUrl + "certify-all"); inputData =
		 * "{\"application\":\"Active Directory\",\"level\":\"High\",\"date\":\"1495677600000\"}"
		 * ; response =
		 * webResource.accept("application/json").type("application/json").post(
		 * ClientResponse.class,inputData); result = response.getEntity(String.class);
		 * System.out.println("application/certify-all: " + result);
		 */
	}
	
	public static void main(String[] args) {
		
		RestClient restClient = new RestClient();
		// fire the get request
		// restClient.getRequest();
		
		// fire the post request
		// restClient.postIdentityAccountRequests();
		// restClient.postIdentityAccountsRequests();
		// restClient.postIdentityEntitlementRequests();
		restClient.postIdentityPasswordRequests();
		restClient.postIdentityCertifyRequests();
		
		restClient.postApplicationRequests();
	}
}
