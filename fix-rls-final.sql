-- ============================================
-- RLS 最终修复：URL 参数传递 Token
-- ============================================

-- 1. 清除所有测试数据和策略
DELETE FROM scripts WHERE cat IN ('test','test2','t','x');
DROP POLICY IF EXISTS "scripts_deny_all" ON scripts;
DROP POLICY IF EXISTS "scripts_sel" ON scripts;
DROP POLICY IF EXISTS "scripts_ins" ON scripts;
DROP POLICY IF EXISTS "scripts_upd" ON scripts;
DROP POLICY IF EXISTS "scripts_del" ON scripts;
DROP POLICY IF EXISTS "pol_scripts" ON scripts;
DROP POLICY IF EXISTS "scripts_select" ON scripts;
DROP POLICY IF EXISTS "lighting_sel" ON lighting;
DROP POLICY IF EXISTS "lighting_ins" ON lighting;
DROP POLICY IF EXISTS "lighting_upd" ON lighting;
DROP POLICY IF EXISTS "lighting_del" ON lighting;
DROP POLICY IF EXISTS "streamers_sel" ON streamers;
DROP POLICY IF EXISTS "streamers_ins" ON streamers;
DROP POLICY IF EXISTS "streamers_upd" ON streamers;
DROP POLICY IF EXISTS "streamers_del" ON streamers;
DROP POLICY IF EXISTS "recaps_sel" ON recaps;
DROP POLICY IF EXISTS "recaps_ins" ON recaps;
DROP POLICY IF EXISTS "recaps_upd" ON recaps;
DROP POLICY IF EXISTS "recaps_del" ON recaps;
DROP POLICY IF EXISTS "work_logs_sel" ON work_logs;
DROP POLICY IF EXISTS "work_logs_ins" ON work_logs;
DROP POLICY IF EXISTS "work_logs_upd" ON work_logs;
DROP POLICY IF EXISTS "work_logs_del" ON work_logs;
DROP POLICY IF EXISTS "config_sel" ON config;
DROP POLICY IF EXISTS "config_ins" ON config;
DROP POLICY IF EXISTS "config_upd" ON config;
DROP POLICY IF EXISTS "config_del" ON config;
DROP POLICY IF EXISTS "sessions_sel" ON sessions;
DROP POLICY IF EXISTS "sessions_del" ON sessions;
DROP POLICY IF EXISTS "pol_sessions_self" ON sessions;

-- 2. 从 URL 路径提取 token（不依赖 request.headers）
CREATE OR REPLACE FUNCTION auth_token()
RETURNS TEXT AS $$
DECLARE
  path TEXT;
  m TEXT[];
BEGIN
  path := current_setting('request.path', true);
  IF path IS NULL THEN RETURN ''; END IF;
  m := regexp_match(path, '[?&]token=([^&]+)');
  IF m IS NULL THEN RETURN ''; END IF;
  RETURN m[1];
EXCEPTION WHEN OTHERS THEN
  RETURN '';
END;
$$ LANGUAGE plpgsql STABLE;

-- 3. is_auth（不变）
CREATE OR REPLACE FUNCTION is_auth()
RETURNS BOOLEAN AS $$
DECLARE
  tok TEXT;
BEGIN
  tok := auth_token();
  IF tok IS NULL OR tok = '' THEN RETURN false; END IF;
  RETURN EXISTS(SELECT 1 FROM sessions WHERE token = tok AND expires_at > NOW());
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- 4. 开启 RLS
ALTER TABLE scripts   ENABLE ROW LEVEL SECURITY;
ALTER TABLE lighting  ENABLE ROW LEVEL SECURITY;
ALTER TABLE streamers ENABLE ROW LEVEL SECURITY;
ALTER TABLE recaps    ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE config    ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions  ENABLE ROW LEVEL SECURITY;

-- 5. 每个表独立策略
CREATE POLICY "s_sel" ON scripts   FOR SELECT USING (is_auth());
CREATE POLICY "s_ins" ON scripts   FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "s_upd" ON scripts   FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "s_del" ON scripts   FOR DELETE USING (is_auth());

CREATE POLICY "l_sel" ON lighting  FOR SELECT USING (is_auth());
CREATE POLICY "l_ins" ON lighting  FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "l_upd" ON lighting  FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "l_del" ON lighting  FOR DELETE USING (is_auth());

CREATE POLICY "st_sel" ON streamers FOR SELECT USING (is_auth());
CREATE POLICY "st_ins" ON streamers FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "st_upd" ON streamers FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "st_del" ON streamers FOR DELETE USING (is_auth());

CREATE POLICY "r_sel" ON recaps    FOR SELECT USING (is_auth());
CREATE POLICY "r_ins" ON recaps    FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "r_upd" ON recaps    FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "r_del" ON recaps    FOR DELETE USING (is_auth());

CREATE POLICY "w_sel" ON work_logs FOR SELECT USING (is_auth());
CREATE POLICY "w_ins" ON work_logs FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "w_upd" ON work_logs FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "w_del" ON work_logs FOR DELETE USING (is_auth());

CREATE POLICY "c_sel" ON config    FOR SELECT USING (is_auth());
CREATE POLICY "c_ins" ON config    FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "c_upd" ON config    FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "c_del" ON config    FOR DELETE USING (is_auth());

CREATE POLICY "ss_sel" ON sessions FOR SELECT USING (token = auth_token());
CREATE POLICY "ss_del" ON sessions FOR DELETE USING (token = auth_token());
