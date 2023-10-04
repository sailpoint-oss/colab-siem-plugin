package com.sailpoint.siem.rest.helper;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ws.rs.core.Response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sailpoint.siem.object.AuditEventsResponseDTO;
import com.sailpoint.siem.object.ErrorResponseDTO;
import com.sailpoint.siem.object.SIEMConstants;
import com.sailpoint.siem.object.SyslogEventsResponseDTO;
import com.sailpoint.siem.util.SIEMUtil;

import sailpoint.api.SailPointContext;
import sailpoint.api.SailPointFactory;
import sailpoint.object.AuditEvent;
import sailpoint.object.Filter;
import sailpoint.object.QueryOptions;
import sailpoint.object.SyslogEvent;
import sailpoint.tools.GeneralException;

import com.sailpoint.iplus.Utils;

/**
 * @author prashant.kagwad (Created on 2/19/20).
 *
 */
public class SIEMExtResourceHelper {
	
	public static final Log		log					= LogFactory.getLog(SIEMExtResourceHelper.class);
	
	private static final int	SYSLOG_EVENT_LIMIT	= 1000;
	private static final int	AUDIT_EVENT_LIMIT	= 1000;
	
	public static Response getSyslogEvents(int manifestLimit, String startIndex, String count, String startTime,
			String endTime, String quickKey) throws GeneralException {
		
		log.trace("Entering getSyslogEvents...");
		
		// Default manifest limit to 1 if zero or non positive number.
		if (manifestLimit <= 0) {
			
			manifestLimit = 1;
		}
		
		// Default start index to 1 if empty.
		int index = SIEMUtil.getInteger(startIndex, 1);
		if (!Utils.isNullOrEmpty(startIndex) && 1 > index) {
			
			//log.debug("Invalid startIndex : " + index);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_START_INDEX,
					SIEMConstants.ERROR_MESSAGE_START_INDEX, SIEMConstants.ERROR_DETAILS_START_INDEX)).build();
		}
		
		// Default count to 1000 if empty.
		int cnt = SIEMUtil.getInteger(count, 1000);
		if (!Utils.isNullOrEmpty(count) && 1 > cnt) {
			
			//log.debug("Invalid count : " + cnt);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_COUNT,
					SIEMConstants.ERROR_MESSAGE_COUNT, SIEMConstants.ERROR_DETAILS_COUNT)).build();
		}
		
		// Default limit to count (if set in the API call) or 1000
		int limit = SIEMUtil.getLimit(cnt, manifestLimit, SYSLOG_EVENT_LIMIT);
		
		// Default it to 0 if empty.
		long startEpochTime = SIEMUtil.getLong(startTime, System.currentTimeMillis() - (24 * 3600 * 1000));
		if (!Utils.isNullOrEmpty(startTime) && 0 >= startEpochTime) {
			
			//log.debug("Invalid startTime : " + startEpochTime);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_START_TIME,
					SIEMConstants.ERROR_MESSAGE_START_TIME, SIEMConstants.ERROR_DETAILS_START_TIME)).build();
		}
		
		// Default it to current timestamp if empty.
		long endEpochTime = SIEMUtil.getLong(endTime, System.currentTimeMillis());
		if (!Utils.isNullOrEmpty(endTime) && 0 >= endEpochTime) {
			
			//log.debug("Invalid endTime : " + endEpochTime);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_END_TIME,
					SIEMConstants.ERROR_MESSAGE_END_TIME, SIEMConstants.ERROR_DETAILS_END_TIME)).build();
		}
		
		if (!Utils.isNullOrEmpty(startTime) && !Utils.isNullOrEmpty(endTime) && startEpochTime > endEpochTime) {
			
			//log.debug("Invalid duration - startTime : " + startEpochTime + ", endTime : " + endEpochTime);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_DURATION,
					SIEMConstants.ERROR_MESSAGE_DURATION, SIEMConstants.ERROR_DETAILS_DURATION)).build();
		}
		
//		log.debug("Getting syslog events for options - index : " + index + ", limit : " + limit + ", startTime : "
//				+ startEpochTime + ", endTime : " + endEpochTime + ", quickKey : " + quickKey);
		
		SailPointContext context = SailPointFactory.getCurrentContext();
		// context.decache(); // Do we need to do this before every call?
		QueryOptions qo = new QueryOptions();
		
		// Add filters only if they are sent in the API call.
		List<Filter> filters = new ArrayList<>();
		// If quickKey is sent in the API call then this overrides the startTime &
		// endTime logic.
		if (!Utils.isNullOrEmpty(quickKey)) {
			
			filters.add(Filter.gt(SIEMConstants.FILTER_QUICK_KEY, quickKey));
		} else {
			
			if (!Utils.isNullOrEmpty(startTime) || !Utils.isNullOrEmpty(endTime)) {
				
				filters.add(Filter.notnull(SIEMConstants.FILTER_CREATED));
			}
			
			if (!Utils.isNullOrEmpty(startTime)) {
				
				filters.add(Filter.gt(SIEMConstants.FILTER_CREATED, new Date(startEpochTime)));
			}
			
			if (!Utils.isNullOrEmpty(endTime)) {
				
				filters.add(Filter.lt(SIEMConstants.FILTER_CREATED, new Date(endEpochTime)));
			}
		}
		
		Filter filter = Filter.and(filters);
		qo.addFilter(filter);
		
		// Adding ordering based on created (ascending).
		List<QueryOptions.Ordering> ordering = new ArrayList<QueryOptions.Ordering>();
		ordering.add(new QueryOptions.Ordering(SIEMConstants.FILTER_CREATED, true));
		qo.setOrderings(ordering);
		qo.setOrderAscending(true);
		
		// Pagination options. This is added irrespective of filters.
		qo.setFirstRow((index - 1) * limit);
		qo.setResultLimit(limit);
		
		int total = context.countObjects(SyslogEvent.class, qo);
		List<SyslogEvent> syslogEvents = context.getObjects(SyslogEvent.class, qo);
		
		//log.debug("Total number of syslog events for the filters : " + total);
		
		log.trace("Exiting getSyslogEvents...");
		return Response.status(Response.Status.OK)
				.entity(new SyslogEventsResponseDTO(syslogEvents.size(), index, total, syslogEvents)).build();
	}
	
	public static Response getAuditEvents(int manifestLimit, String startIndex, String count, String startTime,
			String endTime, String type) throws GeneralException {
		
		log.trace("Entering getAuditEvents...");
		
		// Default start index to 1 if empty.
		int index = SIEMUtil.getInteger(startIndex, 1);
		if (!Utils.isNullOrEmpty(startIndex) && 1 > index) {
			
			//log.debug("Invalid startIndex : " + index);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_START_INDEX,
					SIEMConstants.ERROR_MESSAGE_START_INDEX, SIEMConstants.ERROR_DETAILS_START_INDEX)).build();
		}
		
		// Default count to 1000 if empty.
		int cnt = SIEMUtil.getInteger(count, 1000);
		if (!Utils.isNullOrEmpty(count) && 1 > cnt) {
			
			//log.debug("Invalid count : " + cnt);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_COUNT,
					SIEMConstants.ERROR_MESSAGE_COUNT, SIEMConstants.ERROR_DETAILS_COUNT)).build();
		}
		
		// Default limit to count (if set in the API call) or 1000
		int limit = SIEMUtil.getLimit(cnt, manifestLimit, AUDIT_EVENT_LIMIT);
		
		// Default it to current timestamp minus a day if empty.
		long startEpochTime = SIEMUtil.getLong(startTime, System.currentTimeMillis() - (24 * 3600 * 1000));
		if (!Utils.isNullOrEmpty(startTime) && 0 >= startEpochTime) {
			
			//log.debug("Invalid startTime : " + startEpochTime);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_START_TIME,
					SIEMConstants.ERROR_MESSAGE_START_TIME, SIEMConstants.ERROR_DETAILS_START_TIME)).build();
		}
		
		// Default it to current timestamp if empty.
		long endEpochTime = SIEMUtil.getLong(endTime, System.currentTimeMillis());
		if (!Utils.isNullOrEmpty(endTime) && 0 >= endEpochTime) {
			
			//log.debug("Invalid endTime : " + endEpochTime);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_END_TIME,
					SIEMConstants.ERROR_MESSAGE_END_TIME, SIEMConstants.ERROR_DETAILS_END_TIME)).build();
		}
		
		if (!Utils.isNullOrEmpty(startTime) && !Utils.isNullOrEmpty(endTime) && startEpochTime > endEpochTime) {
			
			//log.debug("Invalid duration - startTime : " + startEpochTime + ", endTime : " + endEpochTime);
			return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(SIEMConstants.ERROR_CODE_DURATION,
					SIEMConstants.ERROR_MESSAGE_DURATION, SIEMConstants.ERROR_DETAILS_DURATION)).build();
		}
		
//		log.debug("Getting audit events for options - index : " + index + ", limit : " + limit + ", startTime : "
//				+ startEpochTime + ", endTime : " + endEpochTime + ", type : " + type);
		
		SailPointContext context = SailPointFactory.getCurrentContext();
		// context.decache(); // Do we need to do this before every call?
		QueryOptions qo = new QueryOptions();
		
		// Add filters only if they are sent in the API call.
		List<Filter> filters = new ArrayList<Filter>();
		if (!Utils.isNullOrEmpty(startTime) || !Utils.isNullOrEmpty(endTime)) {
			
			filters.add(Filter.notnull(SIEMConstants.FILTER_CREATED));
		}
		
		if (!Utils.isNullOrEmpty(startTime)) {
			
			filters.add(Filter.gt(SIEMConstants.FILTER_CREATED, new Date(startEpochTime)));
		}
		
		if (!Utils.isNullOrEmpty(endTime)) {
			
			filters.add(Filter.lt(SIEMConstants.FILTER_CREATED, new Date(endEpochTime)));
		}
		
		if (!Utils.isNullOrEmpty(type)) {
			
			filters.add(Filter.eq(SIEMConstants.FILTER_ACTION, type));
		}
		Filter filter = Filter.and(filters);
		qo.addFilter(filter);
		
		// Adding ordering based on created (ascending).
		List<QueryOptions.Ordering> ordering = new ArrayList<QueryOptions.Ordering>();
		ordering.add(new QueryOptions.Ordering(SIEMConstants.FILTER_CREATED, true));
		qo.setOrderings(ordering);
		qo.setOrderAscending(true);
		
		// Pagination options. This is added irrespective of filters.
		qo.setFirstRow((index - 1) * limit);
		qo.setResultLimit(limit);
		
		int total = context.countObjects(AuditEvent.class, qo);
		List<AuditEvent> auditEvents = context.getObjects(AuditEvent.class, qo);
		
		//log.debug("Total number of audit events for the filters : " + total);
		
		log.trace("Exiting getAuditEvents...");
		return Response.status(Response.Status.OK)
				.entity(new AuditEventsResponseDTO(auditEvents.size(), index, total, auditEvents)).build();
	}
}
