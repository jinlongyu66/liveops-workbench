-- ============================================
-- 最终方案：用 RPC 函数包装所有数据访问
-- 100% 可靠，不依赖 request.headers
-- ============================================

-- 1. 删除失败的 RLS 策略
DROP POLICY IF EXISTS "test_header_sel" ON scripts;
DROP POLICY IF EXISTS "s_sel" ON scripts;
DROP POLICY IF EXISTS "s_ins" ON scripts;
DROP POLICY IF EXISTS "s_upd" ON scripts;
DROP POLICY IF EXISTS "s_del" ON scripts;
DROP POLICY IF EXISTS "l_sel" ON lighting;
DROP POLICY IF EXISTS "l_ins" ON lighting;
DROP POLICY IF EXISTS "l_upd" ON lighting;
DROP POLICY IF EXISTS "l_del" ON lighting;
DROP POLICY IF EXISTS "st_sel" ON streamers;
DROP POLICY IF EXISTS "st_ins" ON streamers;
DROP POLICY IF EXISTS "st_upd" ON streamers;
DROP POLICY IF EXISTS "st_del" ON streamers;
DROP POLICY IF EXISTS "r_sel" ON recaps;
DROP POLICY IF EXISTS "r_ins" ON recaps;
DROP POLICY IF EXISTS "r_upd" ON recaps;
DROP POLICY IF EXISTS "r_del" ON recaps;
DROP POLICY IF EXISTS "w_sel" ON work_logs;
DROP POLICY IF EXISTS "w_ins" ON work_logs;
DROP POLICY IF EXISTS "w_upd" ON work_logs;
DROP POLICY IF EXISTS "w_del" ON work_logs;
DROP POLICY IF EXISTS "c_sel" ON config;
DROP POLICY IF EXISTS "c_ins" ON config;
DROP POLICY IF EXISTS "c_upd" ON config;
DROP POLICY IF EXISTS "c_del" ON config;
DROP POLICY IF EXISTS "ss_sel" ON sessions;
DROP POLICY IF EXISTS "ss_del" ON sessions;

-- 2. 关闭 RLS（改用函数级验证）
ALTER TABLE scripts   DISABLE ROW LEVEL SECURITY;
ALTER TABLE lighting  DISABLE ROW LEVEL SECURITY;
ALTER TABLE streamers DISABLE ROW LEVEL SECURITY;
ALTER TABLE recaps    DISABLE ROW LEVEL SECURITY;
ALTER TABLE work_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE config    DISABLE ROW LEVEL SECURITY;

-- sessions 保持 RLS（只用于 is_auth 检查）
-- ALTER TABLE sessions DISABLE ROW LEVEL SECURITY;

-- 3. Token 验证（简化，直接用参数）
CREATE OR REPLACE FUNCTION check_token(tok TEXT)
RETURNS BOOLEAN AS $$
BEGIN
  IF tok IS NULL OR tok = '' THEN RETURN false; END IF;
  RETURN EXISTS(SELECT 1 FROM sessions WHERE token = tok AND expires_at > NOW());
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- 4. 包装函数：每个表 CRUD

-- scripts
CREATE OR REPLACE FUNCTION api_scripts_list(tok TEXT)
RETURNS SETOF scripts AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM scripts ORDER BY id ASC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_scripts_add(tok TEXT, cat_ TEXT, title_ TEXT, body_ TEXT)
RETURNS scripts AS $$
DECLARE r scripts;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO scripts (cat,title,body) VALUES (cat_,title_,body_) RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_scripts_del(tok TEXT, id_ BIGINT)
RETURNS VOID AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM scripts WHERE id = id_;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- lighting
CREATE OR REPLACE FUNCTION api_lighting_list(tok TEXT)
RETURNS SETOF lighting AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM lighting ORDER BY id ASC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_lighting_add(tok TEXT, name_ TEXT, style_ TEXT, main_ TEXT, fill_ TEXT, rim_ TEXT, beauty_ TEXT, note_ TEXT)
RETURNS lighting AS $$
DECLARE r lighting;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO lighting (name,style,main,fill,rim,beauty,note) VALUES (name_,style_,main_,fill_,rim_,beauty_,note_) RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_lighting_del(tok TEXT, id_ BIGINT)
RETURNS VOID AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM lighting WHERE id = id_;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- streamers
CREATE OR REPLACE FUNCTION api_streamers_list(tok TEXT)
RETURNS SETOF streamers AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM streamers ORDER BY id ASC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_streamers_add(tok TEXT, name_ TEXT, platform_ TEXT, note_ TEXT)
RETURNS streamers AS $$
DECLARE r streamers;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO streamers (name,platform,note,start_date) VALUES (name_,platform_,note_,CURRENT_DATE::text) RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_streamers_del(tok TEXT, id_ BIGINT)
RETURNS VOID AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM streamers WHERE id = id_;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- recaps
CREATE OR REPLACE FUNCTION api_recaps_list(tok TEXT)
RETURNS SETOF recaps AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM recaps ORDER BY date DESC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_recaps_save(tok TEXT, data_ JSONB)
RETURNS recaps AS $$
DECLARE
  r recaps;
  existing_id BIGINT;
BEGIN
  IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
  -- 按 date + streamer 去重
  SELECT id INTO existing_id FROM recaps WHERE date = data_->>'date' AND streamer = data_->>'streamer' LIMIT 1;
  IF existing_id IS NOT NULL THEN
    UPDATE recaps SET
      views = COALESCE((data_->>'views')::BIGINT, 0),
      peak = COALESCE((data_->>'peak')::BIGINT, 0),
      stay = COALESCE((data_->>'stay')::BIGINT, 0),
      fans = COALESCE((data_->>'fans')::BIGINT, 0),
      income = COALESCE((data_->>'income')::NUMERIC, 0),
      payers = COALESCE((data_->>'payers')::BIGINT, 0),
      big_gift = COALESCE((data_->>'big_gift')::BIGINT, 0),
      big_gift_amt = COALESCE((data_->>'big_gift_amt')::NUMERIC, 0),
      pk_count = COALESCE((data_->>'pk_count')::BIGINT, 0),
      pk_win = COALESCE((data_->>'pk_win')::BIGINT, 0),
      hourly = COALESCE(data_->'hourly', '{}'::JSONB),
      peak_time = data_->>'peak_time',
      low_time = data_->>'low_time',
      key_moments = COALESCE(data_->'key_moments', '[]'::JSONB)
    WHERE id = existing_id
    RETURNING * INTO r;
  ELSE
    INSERT INTO recaps (date,streamer,views,peak,stay,fans,income,payers,big_gift,big_gift_amt,pk_count,pk_win,hourly,peak_time,low_time,key_moments)
    VALUES (
      data_->>'date', data_->>'streamer',
      COALESCE((data_->>'views')::BIGINT, 0), COALESCE((data_->>'peak')::BIGINT, 0),
      COALESCE((data_->>'stay')::BIGINT, 0), COALESCE((data_->>'fans')::BIGINT, 0),
      COALESCE((data_->>'income')::NUMERIC, 0), COALESCE((data_->>'payers')::BIGINT, 0),
      COALESCE((data_->>'big_gift')::BIGINT, 0), COALESCE((data_->>'big_gift_amt')::NUMERIC, 0),
      COALESCE((data_->>'pk_count')::BIGINT, 0), COALESCE((data_->>'pk_win')::BIGINT, 0),
      COALESCE(data_->'hourly', '{}'::JSONB), data_->>'peak_time', data_->>'low_time',
      COALESCE(data_->'key_moments', '[]'::JSONB)
    ) RETURNING * INTO r;
  END IF;
  RETURN r;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- work_logs
CREATE OR REPLACE FUNCTION api_work_logs_list(tok TEXT)
RETURNS SETOF work_logs AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM work_logs ORDER BY date DESC, time ASC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_work_logs_add(tok TEXT, date_ TEXT, time_ TEXT, content_ TEXT)
RETURNS work_logs AS $$
DECLARE r work_logs;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO work_logs (date,time,content) VALUES (date_,time_,content_) RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_work_logs_del(tok TEXT, id_ BIGINT)
RETURNS VOID AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM work_logs WHERE id = id_;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- 5. 清理垃圾数据
DELETE FROM scripts WHERE cat IN ('x','hack','test','test2','t');
