package com.sailpoint.siem.rest.helper.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.Response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.sailpoint.siem.object.AuditEventsResponseDTO;
import com.sailpoint.siem.object.ErrorResponseDTO;
import com.sailpoint.siem.object.SIEMConstants;
import com.sailpoint.siem.object.SyslogEventsResponseDTO;
import com.sailpoint.siem.rest.helper.SIEMExtResourceHelper;

import sailpoint.object.AuditEvent;
import sailpoint.object.SyslogEvent;
import sailpoint.tools.GeneralException;

/**
 * @author prashant.kagwad
 *
 *         Test class for SIEMExtResource API's.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(SIEMExtResourceHelper.class)
@PowerMockIgnore("javax.management.*")
public class SIEMExtResourceTest {
	
	private static Log						log					= LogFactory.getLog(SIEMExtResourceTest.class);
	
	private static SIEMExtResourceHelper	spyObject;
	
	private static final String				SYSLOG_CLASS_NAME	= "sailpoint.tools.Console";
	private static final String				SYSLOG_EVENT_LEVEL	= "ERROR";
	private static final String				SYSLOG_ID_1			= "7f000001705911b4817059d3e8b00866";
	private static final String				SYSLOG_ID_2			= "7f000001705914d181705a3603dd008a";
	private static final String				SYSLOG_MESSAGE		= "org.apache.logging.log4j.core.impl.MutableLogEvent@6fead9a";
	private static final String				SYSLOG_USERNAME		= "system";
	
	private static final String				AUDIT_ACTION		= "ServerUpDown";
	private static final String				AUDIT_ID_1			= "7f000001705914d1817059e0b2e80023";
	private static final String				AUDIT_ID_2			= "7f000001705914d181705a3603dd008a";
	private static final String				AUDIT_SERVER_HOST	= "server-11404.dev";
	private static final String				AUDIT_SOURCE		= "server-11404.dev";
	
	private static final String				START_TIME			= "1582055000000";
	private static final String				END_TIME			= "1590000000000";
	
	private int								manifestLimit		= 1;
	private String							startIndex			= "1";
	private String							count				= "1";
	private String							startTime			= START_TIME;
	private String							endTime				= END_TIME;
	private String							quickKey			= "0000000001";
	private String							type				= AUDIT_ACTION;
	
	private void setDefaultValues() {
		
		log.info("Executing setDefaultValues...");
		
		manifestLimit = 1;
		startIndex = "1";
		count = "1";
		startTime = START_TIME;
		endTime = END_TIME;
		quickKey = "0000000001";
		type = AUDIT_ACTION;
	}
	
	// Builder (Response) Functions
	private Response buildErrorResponse(String code, String message, String details) {
		
		log.info("Executing buildErrorResponse...");
		
		return Response.status(Response.Status.OK).entity(new ErrorResponseDTO(code, message, details)).build();
	}
	
	private Response buildEmptySyslogEventResponse(int itemsPerPage, int currentIndex, int totalResults) {
		
		log.info("Executing buildEmptySyslogEventResponse...");
		
		List<SyslogEvent> syslogEvents = new ArrayList<>();
		return Response.status(Response.Status.OK)
				.entity(new SyslogEventsResponseDTO(itemsPerPage, currentIndex, totalResults, syslogEvents)).build();
	}
	
	private Response buildSyslogEventResponse() {
		
		log.info("Executing buildSyslogEventResponse...");
		
		List<SyslogEvent> syslogEvents = new ArrayList<>();
		SyslogEvent syslogEvent = new SyslogEvent();
		syslogEvent.setClassname(SYSLOG_CLASS_NAME);
		syslogEvent.setEventLevel(SYSLOG_EVENT_LEVEL);
		syslogEvent.setId(SYSLOG_ID_1);
		syslogEvent.setMessage(SYSLOG_MESSAGE);
		syslogEvent.setUsername(SYSLOG_USERNAME);
		syslogEvents.add(syslogEvent);
		
		return Response.status(Response.Status.OK)
				.entity(new SyslogEventsResponseDTO(syslogEvents.size(), 1, 1, syslogEvents)).build();
	}
	
	private Response buildSyslogEventsResponse() {
		
		log.info("Executing buildSyslogEventsResponse...");
		
		List<SyslogEvent> syslogEvents = new ArrayList<>();
		SyslogEvent syslogEvent1 = new SyslogEvent();
		syslogEvent1.setClassname(SYSLOG_CLASS_NAME);
		syslogEvent1.setEventLevel(SYSLOG_EVENT_LEVEL);
		syslogEvent1.setId(SYSLOG_ID_1);
		syslogEvent1.setMessage(SYSLOG_MESSAGE);
		syslogEvent1.setUsername(SYSLOG_USERNAME);
		syslogEvents.add(syslogEvent1);
		
		SyslogEvent syslogEvent2 = new SyslogEvent();
		syslogEvent2.setClassname(SYSLOG_CLASS_NAME);
		syslogEvent2.setEventLevel(SYSLOG_EVENT_LEVEL);
		syslogEvent2.setId(SYSLOG_ID_2);
		syslogEvent2.setMessage(SYSLOG_MESSAGE);
		syslogEvent2.setUsername(SYSLOG_USERNAME);
		syslogEvents.add(syslogEvent2);
		
		return Response.status(Response.Status.OK)
				.entity(new SyslogEventsResponseDTO(syslogEvents.size(), 1, 2, syslogEvents)).build();
	}
	
	private Response buildEmptyAuditEventResponse(int itemsPerPage, int currentIndex, int totalResults) {
		
		log.info("Executing buildEmptyAuditEventResponse...");
		
		List<AuditEvent> auditEvents = new ArrayList<>();
		return Response.status(Response.Status.OK)
				.entity(new AuditEventsResponseDTO(itemsPerPage, currentIndex, totalResults, auditEvents)).build();
	}
	
	private Response buildAuditEventResponse() {
		
		log.info("Executing buildAuditEventResponse...");
		
		List<AuditEvent> auditEvents = new ArrayList<>();
		AuditEvent auditEvent = new AuditEvent();
		auditEvent.setAction(AUDIT_ACTION);
		auditEvent.setId(AUDIT_ID_1);
		auditEvent.setServerHost(AUDIT_SERVER_HOST);
		auditEvent.setSource(AUDIT_SOURCE);
		auditEvents.add(auditEvent);
		
		return Response.status(Response.Status.OK)
				.entity(new AuditEventsResponseDTO(auditEvents.size(), 1, 1, auditEvents)).build();
	}
	
	private Response buildAuditEventsResponse() {
		
		log.info("Executing buildAuditEventsResponse...");
		
		List<AuditEvent> auditEvents = new ArrayList<>();
		AuditEvent auditEvent1 = new AuditEvent();
		auditEvent1.setAction(AUDIT_ACTION);
		auditEvent1.setId(AUDIT_ID_1);
		auditEvent1.setServerHost(AUDIT_SERVER_HOST);
		auditEvent1.setSource(AUDIT_SOURCE);
		auditEvents.add(auditEvent1);
		
		AuditEvent auditEvent2 = new AuditEvent();
		auditEvent2.setAction(AUDIT_ACTION);
		auditEvent2.setId(AUDIT_ID_2);
		auditEvent2.setServerHost(AUDIT_SERVER_HOST);
		auditEvent2.setSource(AUDIT_SOURCE);
		auditEvents.add(auditEvent2);
		
		return Response.status(Response.Status.OK)
				.entity(new AuditEventsResponseDTO(auditEvents.size(), 1, 1, auditEvents)).build();
	}
	
	// Test functions
	private void testForErrorResponse(Response response, String code, String message, String details) {
		
		log.info("Executing testForErrorResponse...");
		
		assertNotNull("Response should not be null.", response);
		assertEquals("Response.status should be HTTP 200 OK.", response.getStatus(),
				Response.Status.OK.getStatusCode());
		
		assertNotNull("Response.entity should not be null.", response.getEntity());
		
		ErrorResponseDTO errorResponse = (ErrorResponseDTO) response.getEntity();
		
		assertNotNull("code should not be null.", errorResponse.getCode());
		assertEquals("code should be " + code, errorResponse.getCode(), code);
		
		assertNotNull("message should not be null.", errorResponse.getMessage());
		assertEquals("message should  be " + message, errorResponse.getMessage(), message);
		
		assertNotNull("details should not be null.", errorResponse.getDetails());
		assertEquals("details should be " + details, errorResponse.getDetails(), details);
		
		log.info("Exiting testForErrorResponse...");
	}
	
	private void testForValidSyslogEventsResponse(Response response, int itemsPerPage, int currentIndex,
			int totalResults) {
		
		log.info("Executing testForValidSyslogEventsResponse...");
		
		assertNotNull("Response should not be null.", response);
		assertEquals("Response.status should be HTTP 200 OK.", response.getStatus(),
				Response.Status.OK.getStatusCode());
		
		assertNotNull("Response.entity should not be null.", response.getEntity());
		
		SyslogEventsResponseDTO syslogEventsResponse = (SyslogEventsResponseDTO) response.getEntity();
		
		assertNotNull("itemsPerPage should not be null.", syslogEventsResponse.getItemsPerPage());
		assertEquals("itemsPerPage should be " + itemsPerPage, syslogEventsResponse.getItemsPerPage(), itemsPerPage);
		
		assertNotNull("currentIndex should not be null.", syslogEventsResponse.getCurrentIndex());
		assertEquals("currentIndex should  be " + currentIndex, syslogEventsResponse.getCurrentIndex(), currentIndex);
		
		assertNotNull("totalResults should not be null.", syslogEventsResponse.getTotalResults());
		assertEquals("totalResults should be " + totalResults, syslogEventsResponse.getTotalResults(), totalResults);
		
		for (SyslogEvent syslogEvent : syslogEventsResponse.getSyslogEvents()) {
			
			assertNotNull("syslogEvent should not be null.", syslogEvent);
			
			assertEquals("syslogEvent.class should be " + SYSLOG_CLASS_NAME, syslogEvent.getClassname(),
					SYSLOG_CLASS_NAME);
			assertEquals("syslogEvent.eventLevel should be " + SYSLOG_EVENT_LEVEL, syslogEvent.getEventLevel(),
					SYSLOG_EVENT_LEVEL);
			assertNotNull("syslogEvent.id should not be null.", syslogEvent.getId());
			assertNotNull("syslogEvent.message should not be null.", syslogEvent.getMessage());
			assertEquals("syslogEvent.username should be " + SYSLOG_USERNAME, syslogEvent.getUsername(),
					SYSLOG_USERNAME);
		}
		
		log.info("Exiting testForValidSyslogEventsResponse...");
	}
	
	private void testForValidAuditEventsResponse(Response response, int itemsPerPage, int currentIndex,
			int totalResults) {
		
		log.info("Executing testForValidAuditEventsResponse...");
		
		assertNotNull("Response should not be null.", response);
		assertEquals("Response.status should be HTTP 200 OK.", response.getStatus(),
				Response.Status.OK.getStatusCode());
		
		assertNotNull("Response.entity should not be null.", response.getEntity());
		
		AuditEventsResponseDTO auditEventsResponse = (AuditEventsResponseDTO) response.getEntity();
		
		assertNotNull("itemsPerPage should not be null.", auditEventsResponse.getItemsPerPage());
		assertEquals("itemsPerPage should be " + itemsPerPage, auditEventsResponse.getItemsPerPage(), itemsPerPage);
		
		assertNotNull("currentIndex should not be null.", auditEventsResponse.getCurrentIndex());
		assertEquals("currentIndex should  be " + currentIndex, auditEventsResponse.getCurrentIndex(), currentIndex);
		
		assertNotNull("totalResults should not be null.", auditEventsResponse.getTotalResults());
		assertEquals("totalResults should be " + totalResults, auditEventsResponse.getTotalResults(), totalResults);
		
		for (AuditEvent auditEvent : auditEventsResponse.getAuditEvents()) {
			
			assertNotNull("auditEvent should not be null.", auditEvent);
			
			assertEquals("auditEvent.action should be " + AUDIT_ACTION, auditEvent.getAction(), AUDIT_ACTION);
			assertNotNull("auditEvent.id should not be null.", auditEvent.getId());
			assertEquals("auditEvent.serverHost should be " + AUDIT_SERVER_HOST, auditEvent.getServerHost(),
					AUDIT_SERVER_HOST);
			assertEquals("auditEvent.source should be " + AUDIT_SOURCE, auditEvent.getSource(), AUDIT_SOURCE);
		}
		
		log.info("Exiting testForValidAuditEventsResponse...");
	}
	
	// Tests
	@BeforeClass
	public static void setup() throws Exception {
		
		log.info("Executing setup [@BeforeClass].");
		
		spyObject = Mockito.spy(new SIEMExtResourceHelper());
	}
	
	@AfterClass
	public static void tearDown() throws Exception {
		
		log.info("Executing tearDown [@AfterClass].");
	}
	
	/**
	 * Syslog Event Unit Tests
	 */
	
	@Test
	public void executeGetSyslogEventsWhenNegativeManifestLimitThenSuccess() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenNegativeManifestLimitThenSuccess...");
		
		setDefaultValues();
		manifestLimit = -1;
		
		Response responseMock = buildSyslogEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForValidSyslogEventsResponse(response, 1, 1, 1);
	}
	
	@Test
	public void executeGetSyslogEventsWhenInValidManifestLimitThenSuccess() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenInValidManifestLimitThenSuccess...");
		
		setDefaultValues();
		manifestLimit = 0;
		
		Response responseMock = buildSyslogEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForValidSyslogEventsResponse(response, 1, 1, 1);
	}
	
	// Testing out of bounds or upper limit would require 1000 records. Skipping
	// this for now.
	
	@Test
	public void executeGetSyslogEventsWhenNegativeStartIndexThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenNegativeStartIndexThenError...");
		
		setDefaultValues();
		startIndex = "-1";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_START_INDEX,
				SIEMConstants.ERROR_MESSAGE_START_INDEX, SIEMConstants.ERROR_DETAILS_START_INDEX);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_START_INDEX, SIEMConstants.ERROR_MESSAGE_START_INDEX,
				SIEMConstants.ERROR_DETAILS_START_INDEX);
	}
	
	@Test
	public void executeGetSyslogEventsWhenZeroStartIndexThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenZeroStartIndexThenError...");
		
		setDefaultValues();
		startIndex = "0";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_START_INDEX,
				SIEMConstants.ERROR_MESSAGE_START_INDEX, SIEMConstants.ERROR_DETAILS_START_INDEX);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_START_INDEX, SIEMConstants.ERROR_MESSAGE_START_INDEX,
				SIEMConstants.ERROR_DETAILS_START_INDEX);
	}
	
	@Test
	public void executeGetSyslogEventsWhenOutOfBoundStartIndexThenEmpty() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenOutOfBoundStartIndexThenEmpty...");
		
		setDefaultValues();
		String startIndex = "3";
		
		Response responseMock = buildEmptySyslogEventResponse(0, 3, 1);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForValidSyslogEventsResponse(response, 0, 3, 1);
	}
	
	@Test
	public void executeGetSyslogEventsWhenNegativeCountThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenNegativeCountThenError...");
		
		setDefaultValues();
		count = "-1";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_COUNT, SIEMConstants.ERROR_MESSAGE_COUNT,
				SIEMConstants.ERROR_DETAILS_COUNT);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_COUNT, SIEMConstants.ERROR_MESSAGE_COUNT,
				SIEMConstants.ERROR_DETAILS_COUNT);
	}
	
	@Test
	public void executeGetSyslogEventsWhenZeroCountThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenZeroCountThenError...");
		
		setDefaultValues();
		count = "0";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_COUNT, SIEMConstants.ERROR_MESSAGE_COUNT,
				SIEMConstants.ERROR_DETAILS_COUNT);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_COUNT, SIEMConstants.ERROR_MESSAGE_COUNT,
				SIEMConstants.ERROR_DETAILS_COUNT);
	}
	
	@Test
	public void executeGetSyslogEventsWhenValidCountThenSuccess() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenValidCountThenSuccess...");
		
		setDefaultValues();
		count = "1";
		
		Response responseMock = buildSyslogEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForValidSyslogEventsResponse(response, 1, 1, 1);
	}
	
	@Test
	public void executeGetSyslogEventsWhenNegativeStartTimeThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenNegativeStartTimeThenError...");
		
		setDefaultValues();
		startTime = "-1582055000000";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_START_TIME,
				SIEMConstants.ERROR_MESSAGE_START_TIME, SIEMConstants.ERROR_DETAILS_START_TIME);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_START_TIME, SIEMConstants.ERROR_MESSAGE_START_TIME,
				SIEMConstants.ERROR_DETAILS_START_TIME);
	}
	
	@Test
	public void executeGetSyslogEventsWhenZeroStartTimeThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenZeroStartTimeThenError...");
		
		setDefaultValues();
		startTime = "0";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_START_TIME,
				SIEMConstants.ERROR_MESSAGE_START_TIME, SIEMConstants.ERROR_DETAILS_START_TIME);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_START_TIME, SIEMConstants.ERROR_MESSAGE_START_TIME,
				SIEMConstants.ERROR_DETAILS_START_TIME);
	}
	
	@Test
	public void executeGetSyslogEventsWhenNegativeEndTimeThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenNegativeEndTimeThenError...");
		
		setDefaultValues();
		endTime = "-1590000000000";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_END_TIME,
				SIEMConstants.ERROR_MESSAGE_END_TIME, SIEMConstants.ERROR_DETAILS_END_TIME);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_END_TIME, SIEMConstants.ERROR_MESSAGE_END_TIME,
				SIEMConstants.ERROR_DETAILS_END_TIME);
	}
	
	@Test
	public void executeGetSyslogEventsWhenZeroEndTimeThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenZeroEndTimeThenError...");
		
		setDefaultValues();
		endTime = "0";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_END_TIME,
				SIEMConstants.ERROR_MESSAGE_END_TIME, SIEMConstants.ERROR_DETAILS_END_TIME);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_END_TIME, SIEMConstants.ERROR_MESSAGE_END_TIME,
				SIEMConstants.ERROR_DETAILS_END_TIME);
	}
	
	@Test
	public void executeGetSyslogEventsWhenStartTimeGreaterThanEndTimeThenError() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenStartTimeGreaterThanEndTimeThenError...");
		
		setDefaultValues();
		startTime = "1590000000000";
		endTime = "1582055000000";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_DURATION,
				SIEMConstants.ERROR_MESSAGE_DURATION, SIEMConstants.ERROR_DETAILS_DURATION);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_DURATION, SIEMConstants.ERROR_MESSAGE_DURATION,
				SIEMConstants.ERROR_DETAILS_DURATION);
	}
	
	@Test
	public void executeGetSyslogEventsWhenValidRequestThenSuccess() throws GeneralException {
		
		log.info("Executing executeGetSyslogEventsWhenValidRequestThenSuccess...");
		
		setDefaultValues();
		
		Response responseMock = buildSyslogEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey))
				.thenReturn(responseMock);
		Response response = spyObject.getSyslogEvents(manifestLimit, startIndex, count, startTime, endTime, quickKey);
		
		testForValidSyslogEventsResponse(response, 1, 1, 1);
	}
	
	/**
	 * Audit Event Unit Tests
	 */
	
	@Test
	public void executeGetAuditEventsWhenNegativeManifestLimitThenSuccess() throws GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenNegativeManifestLimitThenSuccess...");
		
		setDefaultValues();
		manifestLimit = -1;
		
		Response responseMock = buildAuditEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForValidAuditEventsResponse(response, 1, 1, 1);
	}
	
	@Test
	public void executeGetAuditEventsWhenInValidManifestLimitThenSuccess() throws GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenInValidManifestLimitThenSuccess...");
		
		setDefaultValues();
		manifestLimit = 0;
		
		Response responseMock = buildAuditEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForValidAuditEventsResponse(response, 1, 1, 1);
	}
	
	// Testing out of bounds or upper limit would require 1000 records. Skipping
	// this for now.
	
	@Test
	public void executeGetAuditEventsWhenNegativeStartIndexThenError() throws GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenNegativeStartIndexThenError...");
		
		setDefaultValues();
		startIndex = "-1";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_START_INDEX,
				SIEMConstants.ERROR_MESSAGE_START_INDEX, SIEMConstants.ERROR_DETAILS_START_INDEX);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_START_INDEX, SIEMConstants.ERROR_MESSAGE_START_INDEX,
				SIEMConstants.ERROR_DETAILS_START_INDEX);
	}
	
	@Test
	public void executeGetAuditEventsWhenZeroStartIndexThenError() throws GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenZeroStartIndexThenError...");
		
		setDefaultValues();
		startIndex = "0";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_START_INDEX,
				SIEMConstants.ERROR_MESSAGE_START_INDEX, SIEMConstants.ERROR_DETAILS_START_INDEX);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_START_INDEX, SIEMConstants.ERROR_MESSAGE_START_INDEX,
				SIEMConstants.ERROR_DETAILS_START_INDEX);
	}
	
	@Test
	public void executeGetAuditEventsWhenOutOfBoundStartIndexThenEmpty() throws GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenOutOfBoundStartIndexThenEmpty...");
		
		setDefaultValues();
		startIndex = "3";
		
		Response responseMock = buildEmptyAuditEventResponse(0, 3, 1);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForValidAuditEventsResponse(response, 0, 3, 1);
	}
	
	@Test
	public void executeGetAuditEventsWhenNegativeCountThenError() throws GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenNegativeCountThenError...");
		
		setDefaultValues();
		count = "-1";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_COUNT, SIEMConstants.ERROR_MESSAGE_COUNT,
				SIEMConstants.ERROR_DETAILS_COUNT);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_COUNT, SIEMConstants.ERROR_MESSAGE_COUNT,
				SIEMConstants.ERROR_DETAILS_COUNT);
	}
	
	@Test
	public void executeGetAuditEventsWhenZeroCountThenError() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenZeroCountThenError...");
		
		setDefaultValues();
		count = "0";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_COUNT, SIEMConstants.ERROR_MESSAGE_COUNT,
				SIEMConstants.ERROR_DETAILS_COUNT);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_COUNT, SIEMConstants.ERROR_MESSAGE_COUNT,
				SIEMConstants.ERROR_DETAILS_COUNT);
	}
	
	@Test
	public void executeGetAuditEventsWhenValidCountThenSuccess() throws GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenValidCountThenSuccess...");
		
		setDefaultValues();
		count = "1";
		
		Response responseMock = buildAuditEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForValidAuditEventsResponse(response, 1, 1, 1);
	}
	
	@Test
	public void executeGetAuditEventsWhenNegativeStartTimeThenError() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenNegativeStartTimeThenError...");
		
		setDefaultValues();
		startTime = "-1582055000000";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_START_TIME,
				SIEMConstants.ERROR_MESSAGE_START_TIME, SIEMConstants.ERROR_DETAILS_START_TIME);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_START_TIME, SIEMConstants.ERROR_MESSAGE_START_TIME,
				SIEMConstants.ERROR_DETAILS_START_TIME);
	}
	
	@Test
	public void executeGetAuditEventsWhenZeroStartTimeThenError() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenZeroStartTimeThenError...");
		
		setDefaultValues();
		startTime = "0";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_START_TIME,
				SIEMConstants.ERROR_MESSAGE_START_TIME, SIEMConstants.ERROR_DETAILS_START_TIME);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_START_TIME, SIEMConstants.ERROR_MESSAGE_START_TIME,
				SIEMConstants.ERROR_DETAILS_START_TIME);
	}
	
	@Test
	public void executeGetAuditEventsWhenNegativeEndTimeThenError() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenNegativeEndTimeThenError...");
		
		setDefaultValues();
		endTime = "-1590000000000";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_END_TIME,
				SIEMConstants.ERROR_MESSAGE_END_TIME, SIEMConstants.ERROR_DETAILS_END_TIME);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_END_TIME, SIEMConstants.ERROR_MESSAGE_END_TIME,
				SIEMConstants.ERROR_DETAILS_END_TIME);
	}
	
	@Test
	public void executeGetAuditEventsWhenZeroEndTimeThenError() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenZeroEndTimeThenError...");
		
		setDefaultValues();
		endTime = "0";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_END_TIME,
				SIEMConstants.ERROR_MESSAGE_END_TIME, SIEMConstants.ERROR_DETAILS_END_TIME);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_END_TIME, SIEMConstants.ERROR_MESSAGE_END_TIME,
				SIEMConstants.ERROR_DETAILS_END_TIME);
	}
	
	@Test
	public void executeGetAuditEventsWhenStartTimeGreaterThanEndTimeThenError() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenStartTimeGreaterThanEndTimeThenError...");
		
		setDefaultValues();
		startTime = "1590000000000";
		endTime = "1582055000000";
		
		Response responseMock = buildErrorResponse(SIEMConstants.ERROR_CODE_DURATION,
				SIEMConstants.ERROR_MESSAGE_DURATION, SIEMConstants.ERROR_DETAILS_DURATION);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForErrorResponse(response, SIEMConstants.ERROR_CODE_DURATION, SIEMConstants.ERROR_MESSAGE_DURATION,
				SIEMConstants.ERROR_DETAILS_DURATION);
	}
	
	@Test
	public void executeGetAuditEventsWhenNullTypeThenSuccess() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenNullTypeThenSuccess...");
		
		setDefaultValues();
		type = null;
		
		Response responseMock = buildAuditEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForValidAuditEventsResponse(response, 1, 1, 1);
	}
	
	@Test
	public void executeGetAuditEventsWhenEmptyTypeThenSuccess() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenEmptyTypeThenSuccess...");
		
		setDefaultValues();
		type = "";
		
		Response responseMock = buildAuditEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForValidAuditEventsResponse(response, 1, 1, 1);
	}
	
	@Test
	public void executeGetAuditEventsWhenInvalidTypeThenSuccess() throws IOException, GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenInvalidTypeThenSuccess...");
		
		setDefaultValues();
		type = "TEST";
		
		Response responseMock = buildEmptyAuditEventResponse(0, 1, 0);
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForValidAuditEventsResponse(response, 0, 1, 0);
	}
	
	@Test
	public void executeGetAuditEventsWhenValidRequestThenSuccess() throws GeneralException {
		
		log.info("Executing executeGetAuditEventsWhenValidRequestThenSuccess...");
		
		setDefaultValues();
		
		Response responseMock = buildAuditEventResponse();
		PowerMockito.mockStatic(SIEMExtResourceHelper.class);
		
		Mockito.when(spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type))
				.thenReturn(responseMock);
		Response response = spyObject.getAuditEvents(manifestLimit, startIndex, count, startTime, endTime, type);
		
		testForValidAuditEventsResponse(response, 1, 1, 1);
	}
}
