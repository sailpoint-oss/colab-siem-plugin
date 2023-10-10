--
-- DB2 DDL plugin script
--

CREATE TABLE siem_alert (
    id varchar(32) NOT NULL,
    alert_id varchar(32) DEFAULT NULL,
    created bigint DEFAULT NULL,
    native_id varchar(255) DEFAULT NULL,
    source_application varchar(255) DEFAULT NULL,
    target_group_name varchar(255) DEFAULT NULL,
    target_group_type varchar(255) DEFAULT NULL,
    alert_level varchar(32) DEFAULT NULL,
    processed_date bigint DEFAULT NULL,
    alert_type varchar(255) DEFAULT NULL,
    action varchar(32) DEFAULT NULL,
    use_workflow CHAR(1),
    PRIMARY KEY (id)
) ;

CREATE INDEX idx_level on siem_alert (alert_level);
CREATE INDEX idx_create on siem_alert (created);
CREATE INDEX idx_alert_type on siem_alert (alert_type);
CREATE INDEX idx_source_application on siem_alert (source_application);

CREATE TABLE siem_overview_data (
    id int NOT NULL,
    type_totals CLOB,
    account_metrics CLOB,
    application_metrics CLOB,
    application_count CLOB,
    PRIMARY KEY (id)
) ;

INSERT INTO siem_overview_data (id, type_totals, account_metrics, application_metrics, application_count) VALUES (1, '[]', '[]', '[]', '[]')
