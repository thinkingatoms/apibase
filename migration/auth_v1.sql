/*
from thinkingatoms.db.postgresql import SQLGenerator

sql_gen = SQLGenerator(
        source=r'/home/tom/dev/thinkingatoms/golang/apibase/migration/auth_v1.sql',
        target=r'/home/tom/dev/thinkingatoms/golang/apibase/migration/auth_v1_final.sql',
        up=r'/home/tom/dev/thinkingatoms/golang/apibase/migration/0002_authdb_up.sql',
        down=r'/home/tom/dev/thinkingatoms/golang/apibase/migration/0002_authdb_down.sql',
        schema='auth',
        shards=None,
        reader_roles=['readonly'],
        writer_roles=['readwrite'],
)
sql_gen.run()
*/

---VIEW ALL TABLES IN SCHEMA auth
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION api
;
SET search_path TO auth
;
---TABLE entity_status:HIST
DROP TABLE IF EXISTS entity_status CASCADE
;
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
---TABLE entity:HIST
DROP TABLE IF EXISTS entity CASCADE
;
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
---TABLE end_user:HIST, CHILD, PK=entity_id
drop table if exists end_user cascade
;
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
---TABLE auth_user:HIST
drop table if exists auth_user cascade
;
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
---TABLE auth_role:HIST
drop table if exists auth_role cascade
;
create table if not exists auth_role (
  auth_role_id serial not null primary key,
  role_name text not null unique,
  last_updated timestamptz not null default current_timestamp,
  last_updated_by text not null default session_user
)
;
insert into auth_role (auth_role_id, role_name) values (0, 'admin') on conflict do nothing
;
---TABLE entitlement:HIST
drop table if exists entitlement cascade
;
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
---TABLE auth_session
drop table if exists auth_session cascade
;
create table if not exists auth_session (
  auth_session_id bigserial not null primary key,
  entity_id bigint not null,
  session_key uuid not null,
  expiration_ts timestamptz not null
)
;
create unique index idx_auth_session_uniq on auth_session (entity_id, session_key)
;
---FUNCTION f_create_auth_session(text, uuid, timestamptz): RW
DROP FUNCTION IF EXISTS f_create_auth_session(text, uuid, timestamptz)
;
CREATE OR REPLACE FUNCTION f_create_auth_session(
  in in_email text,
  in in_session_key uuid,
  in in_expiration_ts timestamptz)
RETURNS bigint AS
$$
  INSERT INTO {schema}.auth_session (entity_id, session_key, expiration_ts)
  SELECT entity_id, in_session_key, in_expiration_ts
  FROM {schema}.end_user
  WHERE email = in_email
  RETURNING entity_id
$$
language 'sql'
;
---TABLE auth_code
drop table if exists auth_code cascade
;
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