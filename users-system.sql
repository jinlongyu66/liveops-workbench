-- ============================================
-- 用户权限系统 + 操作记录
-- ============================================

-- 1. 用户表
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer',
  permissions JSONB DEFAULT '{"modules":["scripts","lighting","streamers","recap","worklog","vips","opponents","schedule","revenue"],"can_edit":false}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. 审计日志表
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  action TEXT NOT NULL,
  table_name TEXT NOT NULL,
  details TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. 扩展 sessions 表
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS role TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS permissions JSONB;

-- 4. RLS 封锁新表
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "block_users" ON users FOR ALL USING (false);
CREATE POLICY "block_audit_logs" ON audit_logs FOR ALL USING (false);

-- 5. 获取用户信息（从 token）
CREATE OR REPLACE FUNCTION get_user_info(tok TEXT)
RETURNS TABLE(username TEXT, role TEXT, permissions JSONB) AS $$
BEGIN
  RETURN QUERY SELECT s.username, s.role, s.permissions FROM sessions s WHERE s.token = tok AND s.expires_at > NOW() LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- 6. 改造登录
DROP FUNCTION IF EXISTS login(password_text TEXT);
DROP FUNCTION IF EXISTS login(tok TEXT, password_text TEXT);

CREATE OR REPLACE FUNCTION login(username_in TEXT, password_in TEXT)
RETURNS JSONB AS $$
DECLARE
  stored_hash TEXT;
  new_token TEXT;
  u users%ROWTYPE;
  result JSONB;
BEGIN
  SELECT * INTO u FROM users WHERE username = username_in;
  IF NOT FOUND THEN RETURN jsonb_build_object('error','用户不存在'); END IF;
  IF u.password_hash != crypt(password_in, u.password_hash) THEN
    RETURN jsonb_build_object('error','密码错误');
  END IF;
  DELETE FROM sessions WHERE expires_at < NOW();
  new_token := gen_random_uuid()::text;
  INSERT INTO sessions (token, username, role, permissions) VALUES (new_token, u.username, u.role, u.permissions);
  RETURN jsonb_build_object('token', new_token, 'username', u.username, 'role', u.role, 'permissions', u.permissions);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 7. 检查 admin 权限
CREATE OR REPLACE FUNCTION is_admin(tok TEXT)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS(SELECT 1 FROM sessions WHERE token = tok AND role = 'admin' AND expires_at > NOW());
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- 8. 审计记录 helper
CREATE OR REPLACE FUNCTION audit_log(tok TEXT, action_ TEXT, table_name_ TEXT, details_ TEXT)
RETURNS VOID AS $$
DECLARE
  uname TEXT;
BEGIN
  SELECT username INTO uname FROM sessions WHERE token = tok AND expires_at > NOW() LIMIT 1;
  IF uname IS NOT NULL THEN
    INSERT INTO audit_logs (username, action, table_name, details) VALUES (uname, action_, table_name_, details_);
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 9. 用户管理 RPC（仅 admin）
CREATE OR REPLACE FUNCTION api_users_list(tok TEXT)
RETURNS SETOF users AS $$
BEGIN IF NOT is_admin(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM users ORDER BY id ASC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_users_add(tok TEXT, username_ TEXT, password_ TEXT, role_ TEXT, permissions_ JSONB)
RETURNS users AS $$
DECLARE r users;
BEGIN IF NOT is_admin(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO users (username, password_hash, role, permissions) VALUES (username_, crypt(password_, gen_salt('bf')), role_, permissions_) RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_users_del(tok TEXT, id_ BIGINT)
RETURNS BOOLEAN AS $$
DECLARE u users;
BEGIN IF NOT is_admin(tok) THEN RAISE 'unauthorized'; END IF;
SELECT * INTO u FROM users WHERE id = id_;
IF u.username = 'admin' THEN RETURN false; END IF;
DELETE FROM users WHERE id = id_;
RETURN true;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_users_update(tok TEXT, id_ BIGINT, permissions_ JSONB, role_ TEXT)
RETURNS users AS $$
DECLARE r users;
BEGIN IF NOT is_admin(tok) THEN RAISE 'unauthorized'; END IF;
UPDATE users SET permissions = permissions_, role = role_ WHERE id = id_ RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- 10. 审计日志查询（仅 admin）
CREATE OR REPLACE FUNCTION api_audit_list(tok TEXT, limit_ BIGINT DEFAULT 200)
RETURNS SETOF audit_logs AS $$
BEGIN IF NOT is_admin(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT limit_;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- 11. 插入默认管理员
INSERT INTO users (username, password_hash, role, permissions)
VALUES ('admin', crypt('admin123', gen_salt('bf')), 'admin', '{"modules":["*"],"can_edit":true}')
ON CONFLICT (username) DO NOTHING;

-- 12. 改造现有写操作 RPC（加审计记录）
-- scripts
CREATE OR REPLACE FUNCTION api_scripts_add(tok TEXT, cat_ TEXT, title_ TEXT, body_ TEXT)
RETURNS scripts AS $$
DECLARE r scripts;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO scripts (cat,title,body) VALUES (cat_,title_,body_) RETURNING * INTO r;
PERFORM audit_log(tok,'add','scripts',title_);
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_scripts_del(tok TEXT, id_ BIGINT)
RETURNS BOOLEAN AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM scripts WHERE id = id_;
PERFORM audit_log(tok,'delete','scripts',id_::TEXT);
RETURN true;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- lighting
CREATE OR REPLACE FUNCTION api_lighting_add(tok TEXT, name_ TEXT, style_ TEXT, main_ TEXT, fill_ TEXT, rim_ TEXT, beauty_ TEXT, note_ TEXT)
RETURNS lighting AS $$
DECLARE r lighting;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO lighting (name,style,main,fill,rim,beauty,note) VALUES (name_,style_,main_,fill_,rim_,beauty_,note_) RETURNING * INTO r;
PERFORM audit_log(tok,'add','lighting',name_);
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_lighting_del(tok TEXT, id_ BIGINT)
RETURNS BOOLEAN AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM lighting WHERE id = id_;
PERFORM audit_log(tok,'delete','lighting',id_::TEXT);
RETURN true;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- streamers
CREATE OR REPLACE FUNCTION api_streamers_add(tok TEXT, name_ TEXT, platform_ TEXT, note_ TEXT)
RETURNS streamers AS $$
DECLARE r streamers;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO streamers (name,platform,note,start_date) VALUES (name_,platform_,note_,CURRENT_DATE::text) RETURNING * INTO r;
PERFORM audit_log(tok,'add','streamers',name_);
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_streamers_del(tok TEXT, id_ BIGINT)
RETURNS BOOLEAN AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM streamers WHERE id = id_;
PERFORM audit_log(tok,'delete','streamers',id_::TEXT);
RETURN true;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- recaps
CREATE OR REPLACE FUNCTION api_recaps_save(tok TEXT, data_ JSONB)
RETURNS recaps AS $$
DECLARE r recaps; existing_id BIGINT;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
SELECT id INTO existing_id FROM recaps WHERE date = data_->>'date' AND streamer = data_->>'streamer' LIMIT 1;
IF existing_id IS NOT NULL THEN
  UPDATE recaps SET views=COALESCE((data_->>'views')::BIGINT,0),peak=COALESCE((data_->>'peak')::BIGINT,0),stay=COALESCE((data_->>'stay')::BIGINT,0),fans=COALESCE((data_->>'fans')::BIGINT,0),income=COALESCE((data_->>'income')::NUMERIC,0),payers=COALESCE((data_->>'payers')::BIGINT,0),big_gift=COALESCE((data_->>'big_gift')::BIGINT,0),big_gift_amt=COALESCE((data_->>'big_gift_amt')::NUMERIC,0),pk_count=COALESCE((data_->>'pk_count')::BIGINT,0),pk_win=COALESCE((data_->>'pk_win')::BIGINT,0),hourly=COALESCE(data_->'hourly','{}'::JSONB),peak_time=data_->>'peak_time',low_time=data_->>'low_time',key_moments=COALESCE(data_->'key_moments','[]'::JSONB) WHERE id=existing_id RETURNING * INTO r;
  PERFORM audit_log(tok,'update','recaps',data_->>'streamer'||' '||data_->>'date');
ELSE
  INSERT INTO recaps (date,streamer,views,peak,stay,fans,income,payers,big_gift,big_gift_amt,pk_count,pk_win,hourly,peak_time,low_time,key_moments) VALUES (data_->>'date',data_->>'streamer',COALESCE((data_->>'views')::BIGINT,0),COALESCE((data_->>'peak')::BIGINT,0),COALESCE((data_->>'stay')::BIGINT,0),COALESCE((data_->>'fans')::BIGINT,0),COALESCE((data_->>'income')::NUMERIC,0),COALESCE((data_->>'payers')::BIGINT,0),COALESCE((data_->>'big_gift')::BIGINT,0),COALESCE((data_->>'big_gift_amt')::NUMERIC,0),COALESCE((data_->>'pk_count')::BIGINT,0),COALESCE((data_->>'pk_win')::BIGINT,0),COALESCE(data_->'hourly','{}'::JSONB),data_->>'peak_time',data_->>'low_time',COALESCE(data_->'key_moments','[]'::JSONB)) RETURNING * INTO r;
  PERFORM audit_log(tok,'add','recaps',data_->>'streamer'||' '||data_->>'date');
END IF;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- work_logs
CREATE OR REPLACE FUNCTION api_work_logs_add(tok TEXT, date_ TEXT, time_ TEXT, content_ TEXT)
RETURNS work_logs AS $$
DECLARE r work_logs;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO work_logs (date,time,content) VALUES (date_,time_,content_) RETURNING * INTO r;
PERFORM audit_log(tok,'add','work_logs',date_||' '||content_);
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_work_logs_del(tok TEXT, id_ BIGINT)
RETURNS BOOLEAN AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM work_logs WHERE id = id_;
PERFORM audit_log(tok,'delete','work_logs',id_::TEXT);
RETURN true;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- vips
CREATE OR REPLACE FUNCTION api_vips_add(tok TEXT, name_ TEXT, platform_ TEXT, total_spent_ NUMERIC, preferences_ TEXT, birthday_ TEXT, notes_ TEXT)
RETURNS vips AS $$
DECLARE r vips;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO vips (name,platform,total_spent,preferences,birthday,notes) VALUES (name_,platform_,total_spent_,preferences_,birthday_,notes_) RETURNING * INTO r;
PERFORM audit_log(tok,'add','vips',name_);
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_vips_del(tok TEXT, id_ BIGINT)
RETURNS BOOLEAN AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM vips WHERE id = id_;
PERFORM audit_log(tok,'delete','vips',id_::TEXT);
RETURN true;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- opponents
CREATE OR REPLACE FUNCTION api_opponents_add(tok TEXT, name_ TEXT, platform_ TEXT, estimated_rank_ TEXT, typical_style_ TEXT, win_count_ BIGINT, loss_count_ BIGINT, strategy_notes_ TEXT)
RETURNS opponents AS $$
DECLARE r opponents;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO opponents (name,platform,estimated_rank,typical_style,win_count,loss_count,strategy_notes) VALUES (name_,platform_,estimated_rank_,typical_style_,win_count_,loss_count_,strategy_notes_) RETURNING * INTO r;
PERFORM audit_log(tok,'add','opponents',name_);
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_opponents_del(tok TEXT, id_ BIGINT)
RETURNS BOOLEAN AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM opponents WHERE id = id_;
PERFORM audit_log(tok,'delete','opponents',id_::TEXT);
RETURN true;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- schedules
CREATE OR REPLACE FUNCTION api_schedules_add(tok TEXT, schedule_date_ TEXT, streamer_ TEXT, time_slot_ TEXT, status_ TEXT, notes_ TEXT)
RETURNS schedules AS $$
DECLARE r schedules;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO schedules (schedule_date,streamer,time_slot,status,notes) VALUES (schedule_date_,streamer_,time_slot_,COALESCE(status_,'scheduled'),notes_) RETURNING * INTO r;
PERFORM audit_log(tok,'add','schedules',streamer_||' '||schedule_date_);
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_schedules_del(tok TEXT, id_ BIGINT)
RETURNS BOOLEAN AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM schedules WHERE id = id_;
PERFORM audit_log(tok,'delete','schedules',id_::TEXT);
RETURN true;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;
