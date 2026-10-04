CREATE TABLE auth_projects (
  project_id TEXT PRIMARY KEY,
  graph_id TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  allow_signups INTEGER NOT NULL DEFAULT 1,
  confirm_email INTEGER NOT NULL DEFAULT 1,
  strict_sessions INTEGER NOT NULL DEFAULT 0,
  site_url TEXT NOT NULL,
  redirect_allowlist TEXT NOT NULL DEFAULT '[]',
  jwt_seconds INTEGER NOT NULL DEFAULT 3600,
  created_at INTEGER NOT NULL
);
CREATE TABLE auth_keys (
  project_id TEXT NOT NULL REFERENCES auth_projects(project_id),
  key_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('publishable','secret')),
  digest TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  PRIMARY KEY(project_id, key_id)
);
CREATE INDEX auth_keys_active ON auth_keys(project_id, digest) WHERE revoked_at IS NULL;
CREATE TABLE auth_users (
  project_id TEXT NOT NULL REFERENCES auth_projects(project_id),
  uid TEXT NOT NULL,
  email TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','banned','deleted')),
  created_at INTEGER NOT NULL,
  last_sign_in INTEGER,
  PRIMARY KEY(project_id, uid),
  UNIQUE(project_id, email)
);
CREATE TABLE auth_credentials (
  project_id TEXT NOT NULL,
  uid TEXT NOT NULL,
  alg TEXT NOT NULL,
  parameters TEXT NOT NULL,
  salt TEXT NOT NULL,
  verifier TEXT NOT NULL,
  PRIMARY KEY(project_id, uid),
  FOREIGN KEY(project_id, uid) REFERENCES auth_users(project_id, uid)
);
CREATE TABLE auth_sessions (
  project_id TEXT NOT NULL,
  sid TEXT NOT NULL,
  uid TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  PRIMARY KEY(project_id, sid),
  FOREIGN KEY(project_id, uid) REFERENCES auth_users(project_id, uid)
);
CREATE INDEX auth_sessions_user ON auth_sessions(project_id, uid, revoked_at);
CREATE TABLE auth_refresh_tokens (
  project_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  sid TEXT NOT NULL,
  parent_hash TEXT,
  issued_at INTEGER NOT NULL,
  used_at INTEGER,
  PRIMARY KEY(project_id, token_hash),
  FOREIGN KEY(project_id, sid) REFERENCES auth_sessions(project_id, sid)
);
CREATE TABLE auth_challenges (
  project_id TEXT NOT NULL,
  challenge_hash TEXT NOT NULL,
  uid TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('confirm','magic','reset')),
  code_hash TEXT,
  redirect_to TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  consumed_at INTEGER,
  PRIMARY KEY(project_id, challenge_hash),
  FOREIGN KEY(project_id, uid) REFERENCES auth_users(project_id, uid)
);
CREATE TABLE auth_email_daily (
  project_id TEXT NOT NULL,
  day TEXT NOT NULL,
  sent INTEGER NOT NULL,
  PRIMARY KEY(project_id, day)
);
CREATE TABLE auth_keys_signing (
  project_id TEXT NOT NULL,
  kid TEXT NOT NULL,
  public_jwk TEXT NOT NULL,
  private_sealed TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(project_id, kid)
);
CREATE TABLE auth_log (
  project_id TEXT NOT NULL,
  event TEXT NOT NULL,
  uid TEXT,
  created_at INTEGER NOT NULL
);
