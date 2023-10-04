package com.sailpoint.siem.rest;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sailpoint.authorization.Authorizer;
import sailpoint.authorization.UnauthorizedAccessException;
import sailpoint.tools.GeneralException;
import sailpoint.web.UserContext;

/**
 * @author adam.creaney (Created on 4/17/17).
 *
 */
@SuppressWarnings("unused")
public class SIEMAuthorizer implements Authorizer {
	
	private static final Log	log		= LogFactory.getLog(SIEMAuthorizer.class);
	
	private Map<String, String>	data	= null;
	
	/**
	 * Constructor.
	 * 
	 * @param CustomPluginObject
	 *            the custom plugin object.
	 */
	public SIEMAuthorizer(Map<String, String> data) {
		
		this.data = data;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void authorize(UserContext userContext) throws GeneralException {
		
		log.debug("Entering Authorizer...");
		
		if (!(userContext.getLoggedInUser().getCapabilityManager().hasCapability("SystemAdministrator")
				|| userContext.getLoggedInUser().getCapabilityManager().hasCapability("SIEMPluginAdministrator"))) {
			
			log.debug("User does not have access to SIEM Plugin.");
			throw new UnauthorizedAccessException("User does not have access to SIEM Plugin.");
		}
		
		log.debug("Exiting Authorizer...");
	}
}
