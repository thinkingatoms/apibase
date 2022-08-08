---VIEW ALL TABLES IN SCHEMA auth
---TABLE entity_status: HIST
DROP TABLE IF EXISTS entity_status CASCADE
;
DROP TABLE IF EXISTS entity_status_hist CASCADE
;
DROP TRIGGER IF EXISTS entity_status_audit ON entity_status
;
---TABLE entity: HIST
DROP TABLE IF EXISTS entity CASCADE
;
DROP TABLE IF EXISTS entity_hist CASCADE
;
DROP TRIGGER IF EXISTS entity_audit ON entity
;
---TABLE end_user: HIST,CHILD,PK=entity_id
drop table if exists end_user cascade
;
DROP TABLE IF EXISTS end_user_hist CASCADE
;
DROP TRIGGER IF EXISTS end_user_audit ON end_user
;
---TABLE auth_user: HIST
drop table if exists auth_user cascade
;
DROP TABLE IF EXISTS auth_user_hist CASCADE
;
DROP TRIGGER IF EXISTS auth_user_audit ON auth_user
;
---VIEW v_auth_user
drop view if exists v_auth_user cascade
;
---TABLE auth_role: HIST
drop table if exists auth_role cascade
;
DROP TABLE IF EXISTS auth_role_hist CASCADE
;
DROP TRIGGER IF EXISTS auth_role_audit ON auth_role
;
---TABLE entitlement: HIST
drop table if exists entitlement cascade
;
DROP TABLE IF EXISTS entitlement_hist CASCADE
;
DROP TRIGGER IF EXISTS entitlement_audit ON entitlement
;
---TABLE auth_session
drop table if exists auth_session cascade
;
---FUNCTION f_create_auth_session(text, uuid, timestamptz): RW
DROP FUNCTION IF EXISTS f_create_auth_session(text, uuid, timestamptz)
;
---TABLE auth_code
drop table if exists auth_code cascade
;
---TABLE auth_message
drop table if exists auth_message cascade
;
