--- CREATE DATABASE app ENCODING 'UTF8'
;
CREATE ROLE readonly NOLOGIN
;
CREATE ROLE readwrite NOLOGIN
;
CREATE ROLE admin NOLOGIN
;
REVOKE CREATE ON SCHEMA public FROM PUBLIC
;
REVOKE ALL ON DATABASE app FROM PUBLIC
;
GRANT CONNECT ON DATABASE app TO readonly
;
GRANT USAGE ON SCHEMA PUBLIC TO readonly
;
GRANT SELECT ON ALL TABLES IN SCHEMA PUBLIC TO readonly
;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly
;
GRANT CONNECT ON DATABASE app TO readwrite
;
GRANT USAGE ON SCHEMA PUBLIC TO readwrite
;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA PUBLIC TO readwrite
;
GRANT ALL ON ALL SEQUENCES IN SCHEMA PUBLIC TO readwrite
;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO readwrite
;
GRANT CONNECT ON DATABASE app TO admin
;
GRANT USAGE, CREATE ON SCHEMA public TO admin
;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA PUBLIC TO admin
;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO admin
;
GRANT readonly TO api
;
GRANT readwrite TO api
;