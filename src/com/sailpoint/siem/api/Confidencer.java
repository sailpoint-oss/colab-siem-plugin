package com.sailpoint.siem.api;

import static java.lang.Math.toIntExact;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sailpoint.siem.object.IdentityLinkDTO;
import com.sailpoint.siem.object.SIEMConstants;

import sailpoint.api.SailPointContext;
import sailpoint.object.Filter;
import sailpoint.object.Identity;
import sailpoint.object.IdentityRequest;
import sailpoint.object.QueryOptions;
import sailpoint.tools.GeneralException;

/**
 * @author adam.creaney (Created on 12/18/18).
 *
 *         This class is intended to provide 'best guess' at which Identity is
 *         being requested, based on an account name that is passed to the SIEM
 *         endpoint.
 *
 *         Most of the time this will be an all or nothing, with account names
 *         mapping to a single identity.
 */
public class Confidencer {
	
	public static final Log				log	= LogFactory.getLog(Confidencer.class);
	
	private Map<String, IdentityLinkDTO>	identityLinks;
	private SailPointContext			context;
	
	/**
	 * Default constructor, requires SailPointContext.
	 *
	 * @param context
	 *            The SailPointContext
	 */
	public Confidencer(SailPointContext context) {
		
		this.identityLinks = new HashMap<String, IdentityLinkDTO>();
		this.context = context;
	}
	
	/**
	 * Constructor
	 *
	 * @param context
	 *            The SailPointContext.
	 * @param identities
	 *            Map of link IDs to the IdentityLink object representing
	 *            interesting attributes on that SailPoint Link object.
	 */
	public Confidencer(SailPointContext context, Map<String, IdentityLinkDTO> identities) {
		
		this.identityLinks = identities;
		this.context = context;
	}
	
	/**
	 * Function (Driver) that will compute the relative 'confidence' that an
	 * Identity cube name returned by the /identityinfo endpoint is the one a SIEM
	 * administrator is looking for.
	 * 
	 * @return
	 * @throws GeneralException
	 */
	public Map<String, Double> evaluate() throws GeneralException {
		
		log.trace("Entering evaluate...");
		
		Map<String, Double> results = new HashMap<>();
		
		List<Identity> identities = getIdentities();
		
		if (identities.size() == 1) {
			
			log.debug("Only 1 identity found, returning with full confidence...");
			results.put(identities.get(0).getName(), 100.00);
		} else {
			
			results = compareIdentitiesAndLinks();
		}
		
		if (log.isDebugEnabled()) {
			
			log.debug("The results are : " + results.toString());
		}
		
		log.trace("Exiting evaluate...");
		return results;
	}
	
	/**
	 * Function to get a list of Identity objects that correlate to the links
	 * returned by account names.
	 *
	 * @return
	 * @throws GeneralException
	 */
	public List<Identity> getIdentities() throws GeneralException {
		
		log.trace("Entering getIdentities...");
		
		List<String> identityIds = new ArrayList<>();
		List<Identity> identities = new ArrayList<>();
		
		for (Map.Entry<String, IdentityLinkDTO> entry : identityLinks.entrySet()) {
			
			IdentityLinkDTO identityLink = entry.getValue();
			log.debug("identityLink : " + identityLink);
			
			String identityId = identityLink.getIdentityId();
			if (!identityIds.contains(identityId)) {
				
				identityIds.add(identityId);
			}
		}
		
		for (String id : identityIds) {
			
			Identity identity = context.getObjectById(Identity.class, id);
			if (null != identity) {
				
				log.debug("The found identity is : " + identity.getName());
				identities.add(identity);
			}
		}
		
		if (log.isDebugEnabled()) {
			
			log.debug("The identities are : " + identities.toString());
		}
		
		log.trace("Exiting getIdentities...");
		return identities;
	}
	
	/**
	 * Function to compare the identity objects and the links to determine the
	 * 'confidence score' of each based on the other entries (eg. if one is really
	 * old and hasn't been updated in years, but one has been updated in the last
	 * few days, it is likely that the active one is of interest vs the inactive.
	 *
	 * @return
	 * @throws GeneralException
	 */
	public Map<String, Double> compareIdentitiesAndLinks() throws GeneralException {
		
		log.trace("Entering compareIdentitiesAndLinks...");
		
		List<String> identityIds = new ArrayList<>();
		
		Map<String, Double> confidenceMap = new HashMap<>();
		
		for (Map.Entry<String, IdentityLinkDTO> entry : identityLinks.entrySet()) {
			
			IdentityLinkDTO identityLink = entry.getValue();
			String identityId = identityLink.getIdentityId();
			if (!identityIds.contains(identityId)) {
				
				identityIds.add(identityId);
			}
		}
		
		// TODO right now this is just flat saying the confidence is split evenly
		for (String identityId : identityIds) {
			
			Identity identity = context.getObjectById(Identity.class, identityId);
			// TODO calculate based on attribute weights
			int roleScore = getRolesScore(identity);
			int accountScore = getAccountScore(identity);
			int accessRequestScore = getAccessRequestScore(identity);
			int modifiedScore = getModifiedScore(identity);
			int lastLoginScore = getLastLoginScore(identity);
			
			double finalScore = calculateFinalScore(roleScore, accountScore, accessRequestScore, modifiedScore,
					lastLoginScore);
			
			String identityName = identity.getName();
			confidenceMap.put(identityName, finalScore);
		}
		
		log.trace("Exiting compareIdentitiesAndLinks...");
		return confidenceMap;
	}
	
	/**
	 * Function that will combine all the calculated scores to determine the overall
	 * score for confidence.
	 *
	 * @param roleScore
	 *            Role score calculated.
	 * @param accountScore
	 *            Account score calculated.
	 * @param accessRequestScore
	 *            Access request score calculated.
	 * @param modifiedScore
	 *            Identity modified score calculated.
	 * @param lastLoginScore
	 *            Identity last login score calculated.
	 * @return
	 */
	public double calculateFinalScore(int roleScore, int accountScore, int accessRequestScore, int modifiedScore,
			int lastLoginScore) {
		
		log.trace("Entering calculateTotalScore...");
		
		double totalScore = 0;
		double finalScore = 0;
		int totalCriteria = SIEMConstants.CONFIDENCER_TOTAL_CRITERIA;
		totalScore = roleScore + accountScore + accessRequestScore + (modifiedScore / 2) + lastLoginScore;
		finalScore = totalScore / totalCriteria;
		
		log.trace("Exiting calculateTotalScore with score : " + finalScore);
		return finalScore;
	}
	
	/**
	 * Function to return in integer score between 1-100 based on role assignments.
	 * 
	 * @param identity
	 *            The identity being evaluated.
	 * @return
	 */
	public int getRolesScore(Identity identity) {
		
		log.trace("Entering getRolesScore...");
		
		int score = 0;
		int assignedRoleCount = identity.getAssignedRoles().size();
		int detectedRolesCount = identity.getDetectedRoles().size();
		int totalRoles = assignedRoleCount + detectedRolesCount;
		if (totalRoles > SIEMConstants.CONFIDENCER_ROLE_COUNT) {
			
			score = 100;
		} else {
			
			score = totalRoles * 30;
		}
		
		log.trace("Exiting getRolesScore with score : " + score);
		return score;
	}
	
	/**
	 * Function to return an integer score between 1-100 based on account counts.
	 * 
	 * @param identity
	 *            The identity being evaluated.
	 * @return
	 */
	public int getAccountScore(Identity identity) {
		
		log.trace("Entering getAccountScore...");
		
		int score = 0;
		int linkCount = identity.getLinks().size();
		if (linkCount > SIEMConstants.CONFIDENCER_LINK_COUNT) {
			
			score = 100;
		} else {
			
			score = linkCount * 30;
		}
		
		// TODO we could make this more cleve and check link attributes as well
		// (created/modified/ents etc)
		
		log.trace("Exiting getAccountScore with score : " + score);
		return score;
	}
	
	/**
	 * Function to return an integer score between 1-100 based on access request
	 * counts (submitted and target of).
	 * 
	 * @param identity
	 *            The identity being evaluated.
	 * @return
	 */
	public int getAccessRequestScore(Identity identity) throws GeneralException {
		
		log.trace("Entering getAccessRequestScore...");
		
		int score = 0;
		int subScore = 0;
		int targScore = 0;
		String identityId = identity.getId();
		
		QueryOptions qoSubmitted = new QueryOptions();
		Filter requester = Filter.eq(SIEMConstants.SCORE_REQUESTER_ID, identityId);
		qoSubmitted.addFilter(requester);
		
		int submittedScount = context.countObjects(IdentityRequest.class, qoSubmitted);
		
		QueryOptions qoTargeted = new QueryOptions();
		Filter target = Filter.eq(SIEMConstants.SCORE_TARGET_ID, identityId);
		qoTargeted.addFilter(target);
		
		int targetCount = context.countObjects(IdentityRequest.class, qoTargeted);
		
		if (submittedScount > SIEMConstants.CONFIDENCER_SUBMITTED_COUNT) {
			
			subScore = 100;
		} else {
			
			subScore = submittedScount * 20;
		}
		
		if (targetCount > SIEMConstants.CONFIDENCER_TARGET_COUNT) {
			
			targScore = 100;
		} else {
			
			targScore = targetCount * 20;
		}
		
		score = (subScore + targScore) / 2;
		
		log.trace("Exiting getAccessRequestScore with score : " + score);
		return score;
	}
	
	/**
	 * Function to return an integer score between 1-100 based on modified timestamp
	 * for Identity.
	 * 
	 * @param identity
	 *            The identity being evaluated.
	 * @return
	 */
	public int getModifiedScore(Identity identity) {
		
		log.trace("Entering getModifiedScore...");
		
		int score = 0;
		Date lastModified = identity.getModified();
		Date now = new Date();
		long diff = now.getTime() - lastModified.getTime();
		int days = toIntExact(TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS));
		
		if (days <= SIEMConstants.CONFIDENCER_DAY_COUNT) {
			
			score = 100 - (days * 10);
		} else {
			
			score = 10;
		}
		
		log.trace("Exiting getModifiedScore with score :  " + score);
		return score;
	}
	
	/**
	 * Function to return an integer score between 1-100 based on last login.
	 * 
	 * @param identity
	 *            The identity being evaluated.
	 * @return
	 */
	public int getLastLoginScore(Identity identity) {
		
		log.trace("Entering getLastLoginScore...");
		
		int score = 0;
		Date lastLogin = identity.getLastLogin();
		// if no last login date, never logged in, set to 0
		if (lastLogin != null) {
			
			Date now = new Date();
			
			long diff = now.getTime() - lastLogin.getTime();
			int days = toIntExact(TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS));
			
			if (days <= SIEMConstants.CONFIDENCER_DAYS_SINCE_LOGIN_COUNT) {
				
				score = 100 - (days * 10);
			} else {
				
				score = 10;
			}
		} else {
			
			score = 0;
		}
		
		log.trace("Exiting getLastLoginScore with score : " + score);
		return score;
	}
	
	/**
	 * Function to count the total identities present in the links (some links will
	 * have the same identity_id that they correlate to.
	 *
	 * @return
	 */
	public int countIdentities() {
		
		log.trace("Entering countIdentities...");
		
		int ret;
		if (identityLinks.isEmpty()) {
			
			ret = 0;
		} else if (identityLinks.size() == 1) {
			
			ret = 1;
		} else {
			
			List<String> identityIds = new ArrayList<>();
			for (Map.Entry<String, IdentityLinkDTO> entry : identityLinks.entrySet()) {
				
				IdentityLinkDTO identityLink = entry.getValue();
				String identityId = identityLink.getIdentityId();
				if (!identityIds.contains(identityId)) {
					
					identityIds.add(identityId);
				}
			}
			ret = identityIds.size();
		}
		
		log.trace("Existing countIdentities with : " + ret);
		return ret;
	}
}
