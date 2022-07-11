
---VIEW ALL TABLES IN SCHEMA auth
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION api
;
SET search_path TO auth
;
GRANT SELECT ON ALL TABLES IN SCHEMA auth TO readonly
;
---TABLE entity_status: HIST
CREATE TABLE IF NOT EXISTS entity_status (
entity_status_id serial not null primary key,
entity_type text not null,
status_name text not null,
last_updated timestamptz not null default current_timestamp,
last_updated_by text not null default session_user
)
;
INSERT INTO entity_status (entity_status_id, entity_type, status_name)
VALUES (0, '', '') ON CONFLICT DO NOTHING
;
INSERT INTO entity_status (entity_type, status_name) VALUES
('user', 'verified'),
('user', 'unverified')
ON CONFLICT DO NOTHING
;
CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_status_uniq ON entity_status (entity_type, status_name)
;
GRANT SELECT ON entity_status TO readonly
;
GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON entity_status TO readwrite
;
GRANT ALL ON SEQUENCE entity_status_entity_status_id_seq TO readwrite
;
CREATE TABLE IF NOT EXISTS entity_status_hist
(
entity_status_hist_id bigserial not null primary key,
is_initial bool not null default false,
valid_from_ts timestamptz not null,
valid_to_ts timestamptz not null,
like entity_status
)
;
CREATE INDEX idx_entity_status_hist_trg ON entity_status_hist
(entity_status_id, valid_from_ts, valid_to_ts desc)
;
CREATE OR REPLACE FUNCTION entity_status_audit()
RETURNS TRIGGER AS
$$
DECLARE
   ts timestamptz;
BEGIN
    SELECT current_timestamp INTO ts;

    IF (TG_OP = 'DELETE') THEN
        UPDATE auth.entity_status_hist
          SET valid_to_ts = ts
        WHERE entity_status_id = OLD.entity_status_id
          AND ts BETWEEN valid_from_ts AND valid_to_ts;
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        UPDATE auth.entity_status_hist
          SET valid_to_ts = ts
        WHERE entity_status_id = OLD.entity_status_id
          AND  ts BETWEEN valid_from_ts and valid_to_ts;

        INSERT INTO auth.entity_status_hist
        SELECT nextval('auth.entity_status_hist_entity_status_hist_id_seq'::regclass),
        false, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO auth.entity_status_hist
        SELECT nextval('auth.entity_status_hist_entity_status_hist_id_seq'::regclass),
        true, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$
LANGUAGE 'plpgsql'
;
CREATE TRIGGER entity_status_audit
AFTER INSERT OR UPDATE OR DELETE ON entity_status
FOR EACH ROW EXECUTE PROCEDURE entity_status_audit()
;
GRANT ALL ON SEQUENCE entity_status_hist_entity_status_hist_id_seq TO readwrite
;
---TABLE entity: HIST
CREATE TABLE IF NOT EXISTS entity (
entity_id bigserial not null primary key,
entity_type text not null,
entity_uuid uuid not null, -- name used for urls
display_name text not null, -- name used to display entity
details jsonb not null,
entity_status_id int not null references entity_status(entity_status_id),
last_updated timestamptz not null default current_timestamp,
last_updated_by varchar(100) not null default session_user
)
;
CREATE UNIQUE INDEX idx_entity_uuid on entity (entity_uuid)
;
GRANT SELECT ON entity TO readonly
;
GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON entity TO readwrite
;
GRANT ALL ON SEQUENCE entity_entity_id_seq TO readwrite
;
CREATE TABLE IF NOT EXISTS entity_hist
(
entity_hist_id bigserial not null primary key,
is_initial bool not null default false,
valid_from_ts timestamptz not null,
valid_to_ts timestamptz not null,
like entity
)
;
CREATE INDEX idx_entity_hist_trg ON entity_hist
(entity_id, valid_from_ts, valid_to_ts desc)
;
CREATE OR REPLACE FUNCTION entity_audit()
RETURNS TRIGGER AS
$$
DECLARE
   ts timestamptz;
BEGIN
    SELECT current_timestamp INTO ts;

    IF (TG_OP = 'DELETE') THEN
        UPDATE auth.entity_hist
          SET valid_to_ts = ts
        WHERE entity_id = OLD.entity_id
          AND ts BETWEEN valid_from_ts AND valid_to_ts;
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        UPDATE auth.entity_hist
          SET valid_to_ts = ts
        WHERE entity_id = OLD.entity_id
          AND  ts BETWEEN valid_from_ts and valid_to_ts;

        INSERT INTO auth.entity_hist
        SELECT nextval('auth.entity_hist_entity_hist_id_seq'::regclass),
        false, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO auth.entity_hist
        SELECT nextval('auth.entity_hist_entity_hist_id_seq'::regclass),
        true, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$
LANGUAGE 'plpgsql'
;
CREATE TRIGGER entity_audit
AFTER INSERT OR UPDATE OR DELETE ON entity
FOR EACH ROW EXECUTE PROCEDURE entity_audit()
;
GRANT ALL ON SEQUENCE entity_hist_entity_hist_id_seq TO readwrite
;
---TABLE end_user: HIST,CHILD,PK=entity_id
create table if not exists end_user (
email text not null,
fail_count int not null default 0
) inherits (entity)
;
create unique index idx_end_user_email on end_user (email)
;
create unique index idx_end_user_pk on end_user (entity_id)
;
INSERT INTO end_user
(entity_id, entity_type, entity_uuid, display_name, details, entity_status_id, email)
VALUES (0, '', '00000000-0000-0000-0000-000000000000', '', '{}'::jsonb, 0, '')
ON CONFLICT DO NOTHING
;
GRANT SELECT ON end_user TO readonly
;
GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON end_user TO readwrite
;
CREATE TABLE IF NOT EXISTS end_user_hist
(
end_user_hist_id bigserial not null primary key,
is_initial bool not null default false,
valid_from_ts timestamptz not null,
valid_to_ts timestamptz not null,
like end_user
)
;
CREATE INDEX idx_end_user_hist_trg ON end_user_hist
(entity_id, valid_from_ts, valid_to_ts desc)
;
CREATE OR REPLACE FUNCTION end_user_audit()
RETURNS TRIGGER AS
$$
DECLARE
   ts timestamptz;
BEGIN
    SELECT current_timestamp INTO ts;

    IF (TG_OP = 'DELETE') THEN
        UPDATE auth.end_user_hist
          SET valid_to_ts = ts
        WHERE entity_id = OLD.entity_id
          AND ts BETWEEN valid_from_ts AND valid_to_ts;
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        UPDATE auth.end_user_hist
          SET valid_to_ts = ts
        WHERE entity_id = OLD.entity_id
          AND  ts BETWEEN valid_from_ts and valid_to_ts;

        INSERT INTO auth.end_user_hist
        SELECT nextval('auth.end_user_hist_end_user_hist_id_seq'::regclass),
        false, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO auth.end_user_hist
        SELECT nextval('auth.end_user_hist_end_user_hist_id_seq'::regclass),
        true, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$
LANGUAGE 'plpgsql'
;
CREATE TRIGGER end_user_audit
AFTER INSERT OR UPDATE OR DELETE ON end_user
FOR EACH ROW EXECUTE PROCEDURE end_user_audit()
;
GRANT ALL ON SEQUENCE end_user_hist_end_user_hist_id_seq TO readwrite
;
---TABLE auth_user: HIST
create table if not exists auth_user (
auth_user_id bigserial not null primary key,
user_id bigint not null references end_user(entity_id),
auth_method text not null,
hashed_validation text not null,
details jsonb not null,
last_updated timestamptz not null default current_timestamp,
last_updated_by text not null default session_user
)
;
create unique index idx_auth_user_ext on auth_user (hashed_validation, auth_method)
;
create unique index idx_auth_user_uniq on auth_user (user_id, auth_method)
;
insert into auth_user (auth_user_id, user_id, auth_method, hashed_validation, details)
values (0, 0, 'client', md5(random()::text), '{}'::jsonb)
on conflict do nothing
;
GRANT SELECT ON auth_user TO readonly
;
GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON auth_user TO readwrite
;
GRANT ALL ON SEQUENCE auth_user_auth_user_id_seq TO readwrite
;
CREATE TABLE IF NOT EXISTS auth_user_hist
(
auth_user_hist_id bigserial not null primary key,
is_initial bool not null default false,
valid_from_ts timestamptz not null,
valid_to_ts timestamptz not null,
like auth_user
)
;
CREATE INDEX idx_auth_user_hist_trg ON auth_user_hist
(auth_user_id, valid_from_ts, valid_to_ts desc)
;
CREATE OR REPLACE FUNCTION auth_user_audit()
RETURNS TRIGGER AS
$$
DECLARE
   ts timestamptz;
BEGIN
    SELECT current_timestamp INTO ts;

    IF (TG_OP = 'DELETE') THEN
        UPDATE auth.auth_user_hist
          SET valid_to_ts = ts
        WHERE auth_user_id = OLD.auth_user_id
          AND ts BETWEEN valid_from_ts AND valid_to_ts;
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        UPDATE auth.auth_user_hist
          SET valid_to_ts = ts
        WHERE auth_user_id = OLD.auth_user_id
          AND  ts BETWEEN valid_from_ts and valid_to_ts;

        INSERT INTO auth.auth_user_hist
        SELECT nextval('auth.auth_user_hist_auth_user_hist_id_seq'::regclass),
        false, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO auth.auth_user_hist
        SELECT nextval('auth.auth_user_hist_auth_user_hist_id_seq'::regclass),
        true, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$
LANGUAGE 'plpgsql'
;
CREATE TRIGGER auth_user_audit
AFTER INSERT OR UPDATE OR DELETE ON auth_user
FOR EACH ROW EXECUTE PROCEDURE auth_user_audit()
;
GRANT ALL ON SEQUENCE auth_user_hist_auth_user_hist_id_seq TO readwrite
;
---TABLE auth_role: HIST
create table if not exists auth_role (
auth_role_id serial not null primary key,
role_name text not null unique,
last_updated timestamptz not null default current_timestamp,
last_updated_by text not null default session_user
)
;
insert into auth_role (auth_role_id, role_name) values (0, 'admin') on conflict do nothing
;
GRANT SELECT ON auth_role TO readonly
;
GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON auth_role TO readwrite
;
GRANT ALL ON SEQUENCE auth_role_auth_role_id_seq TO readwrite
;
CREATE TABLE IF NOT EXISTS auth_role_hist
(
auth_role_hist_id bigserial not null primary key,
is_initial bool not null default false,
valid_from_ts timestamptz not null,
valid_to_ts timestamptz not null,
like auth_role
)
;
CREATE INDEX idx_auth_role_hist_trg ON auth_role_hist
(auth_role_id, valid_from_ts, valid_to_ts desc)
;
CREATE OR REPLACE FUNCTION auth_role_audit()
RETURNS TRIGGER AS
$$
DECLARE
   ts timestamptz;
BEGIN
    SELECT current_timestamp INTO ts;

    IF (TG_OP = 'DELETE') THEN
        UPDATE auth.auth_role_hist
          SET valid_to_ts = ts
        WHERE auth_role_id = OLD.auth_role_id
          AND ts BETWEEN valid_from_ts AND valid_to_ts;
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        UPDATE auth.auth_role_hist
          SET valid_to_ts = ts
        WHERE auth_role_id = OLD.auth_role_id
          AND  ts BETWEEN valid_from_ts and valid_to_ts;

        INSERT INTO auth.auth_role_hist
        SELECT nextval('auth.auth_role_hist_auth_role_hist_id_seq'::regclass),
        false, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO auth.auth_role_hist
        SELECT nextval('auth.auth_role_hist_auth_role_hist_id_seq'::regclass),
        true, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$
LANGUAGE 'plpgsql'
;
CREATE TRIGGER auth_role_audit
AFTER INSERT OR UPDATE OR DELETE ON auth_role
FOR EACH ROW EXECUTE PROCEDURE auth_role_audit()
;
GRANT ALL ON SEQUENCE auth_role_hist_auth_role_hist_id_seq TO readwrite
;
---TABLE entitlement: HIST
create table if not exists entitlement (
entitlement_id bigserial not null primary key,
user_id bigint not null references end_user(entity_id), -- the user, for instance user Joe Smith
role_id int not null references auth_role(auth_role_id), -- the role
target_id bigint not null, -- any (other) entity where the entitlement is applicable
last_updated timestamptz not null default current_timestamp,
last_updated_by text not null default session_user
)
;
create unique index idx_entitlement_uniq on entitlement (user_id, role_id, target_id)
;
insert into entitlement (user_id, role_id, target_id) values (0, 0, 0) on conflict do nothing
;
GRANT SELECT ON entitlement TO readonly
;
GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON entitlement TO readwrite
;
GRANT ALL ON SEQUENCE entitlement_entitlement_id_seq TO readwrite
;
CREATE TABLE IF NOT EXISTS entitlement_hist
(
entitlement_hist_id bigserial not null primary key,
is_initial bool not null default false,
valid_from_ts timestamptz not null,
valid_to_ts timestamptz not null,
like entitlement
)
;
CREATE INDEX idx_entitlement_hist_trg ON entitlement_hist
(entitlement_id, valid_from_ts, valid_to_ts desc)
;
CREATE OR REPLACE FUNCTION entitlement_audit()
RETURNS TRIGGER AS
$$
DECLARE
   ts timestamptz;
BEGIN
    SELECT current_timestamp INTO ts;

    IF (TG_OP = 'DELETE') THEN
        UPDATE auth.entitlement_hist
          SET valid_to_ts = ts
        WHERE entitlement_id = OLD.entitlement_id
          AND ts BETWEEN valid_from_ts AND valid_to_ts;
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        UPDATE auth.entitlement_hist
          SET valid_to_ts = ts
        WHERE entitlement_id = OLD.entitlement_id
          AND  ts BETWEEN valid_from_ts and valid_to_ts;

        INSERT INTO auth.entitlement_hist
        SELECT nextval('auth.entitlement_hist_entitlement_hist_id_seq'::regclass),
        false, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO auth.entitlement_hist
        SELECT nextval('auth.entitlement_hist_entitlement_hist_id_seq'::regclass),
        true, ts, '2250-01-01 UTC', NEW.*;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$
LANGUAGE 'plpgsql'
;
CREATE TRIGGER entitlement_audit
AFTER INSERT OR UPDATE OR DELETE ON entitlement
FOR EACH ROW EXECUTE PROCEDURE entitlement_audit()
;
GRANT ALL ON SEQUENCE entitlement_hist_entitlement_hist_id_seq TO readwrite
;
---TABLE auth_session
create table if not exists auth_session (
auth_session_id bigserial not null primary key,
entity_id bigint not null,
session_key uuid not null,
expiration_ts timestamptz not null
)
;
create unique index idx_auth_session_uniq on auth_session (entity_id, session_key)
;
GRANT SELECT ON auth_session TO readonly
;
GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON auth_session TO readwrite
;
GRANT ALL ON SEQUENCE auth_session_auth_session_id_seq TO readwrite
;
---FUNCTION f_create_auth_session(text, uuid, timestamptz): RW
CREATE OR REPLACE FUNCTION f_create_auth_session(
in in_email text,
in in_session_key uuid,
in in_expiration_ts timestamptz)
RETURNS bigint AS
$$
INSERT INTO auth.auth_session (entity_id, session_key, expiration_ts)
SELECT entity_id, in_session_key, in_expiration_ts
FROM auth.end_user
WHERE email = in_email
RETURNING entity_id
$$
language 'sql'
;
GRANT EXECUTE ON FUNCTION f_create_auth_session(text, uuid, timestamptz) TO readwrite
;
GRANT EXECUTE ON FUNCTION f_create_auth_session(text, uuid, timestamptz) TO readonly
;
---TABLE auth_code
create table if not exists auth_code (
auth_code_id bigserial not null primary key,
auth_method text not null,
auth_id text not null,
code text not null,
expiration_ts timestamptz not null,
ip_address text not null,
fail_count int not null default 0,
last_updated timestamptz not null default current_timestamp
)
;
create unique index idx_phone_code_uniq on auth_code (auth_method, auth_id)
;
create index idx_phone_code_ip on auth_code (ip_address)
;
GRANT SELECT ON auth_code TO readonly
;
GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON auth_code TO readwrite
;
GRANT ALL ON SEQUENCE auth_code_auth_code_id_seq TO readwrite
;