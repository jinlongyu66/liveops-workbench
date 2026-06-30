-- ============================================
-- RLS 修复 v3：改用 request.header.xxx GUC
-- PostgREST 把每个请求头暴露为独立 GUC
-- ============================================

-- 先检查 RLS 是否启用
SELECT schemaname || '.' || tablename AS tbl, row_level_security AS rls_on
FROM pg_tables WHERE schemaname = 'public'
AND tablename IN ('scripts','lighting','streamers','recaps','work_logs','config','sessions');

-- 简化 auth_token：直接从独立 GUC 读取
CREATE OR REPLACE FUNCTION auth_token()
RETURNS TEXT AS $$
BEGIN
  RETURN COALESCE(
    current_setting('request.header.x-session-token', true),
    ''
  );
END;
$$ LANGUAGE plpgsql STABLE;

-- 加固 is_auth
CREATE OR REPLACE FUNCTION is_auth()
RETURNS BOOLEAN AS $$
DECLARE
  tok TEXT;
BEGIN
  tok := auth_token();
  IF tok IS NULL OR tok = '' THEN
    RETURN false;
  END IF;
  RETURN EXISTS(
    SELECT 1 FROM sessions
    WHERE token = tok
    AND expires_at > NOW()
  );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- 如果没有 RLS，先启用
ALTER TABLE scripts   ENABLE ROW LEVEL SECURITY;
ALTER TABLE lighting  ENABLE ROW LEVEL SECURITY;
ALTER TABLE streamers ENABLE ROW LEVEL SECURITY;
ALTER TABLE recaps    ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE config    ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions  ENABLE ROW LEVEL SECURITY;

-- 删掉所有旧策略
DROP POLICY IF EXISTS "pol_scripts"      ON scripts;
DROP POLICY IF EXISTS "pol_lighting"     ON lighting;
DROP POLICY IF EXISTS "pol_streamers"    ON streamers;
DROP POLICY IF EXISTS "pol_recaps"       ON recaps;
DROP POLICY IF EXISTS "pol_work_logs"    ON work_logs;
DROP POLICY IF EXISTS "pol_config"       ON config;
DROP POLICY IF EXISTS "scripts_select"   ON scripts;
DROP POLICY IF EXISTS "scripts_insert"   ON scripts;
DROP POLICY IF EXISTS "scripts_update"   ON scripts;
DROP POLICY IF EXISTS "scripts_delete"   ON scripts;
DROP POLICY IF EXISTS "lighting_select"  ON lighting;
DROP POLICY IF EXISTS "lighting_insert"  ON lighting;
DROP POLICY IF EXISTS "lighting_update"  ON lighting;
DROP POLICY IF EXISTS "lighting_delete"  ON lighting;
DROP POLICY IF EXISTS "streamers_select" ON streamers;
DROP POLICY IF EXISTS "streamers_insert" ON streamers;
DROP POLICY IF EXISTS "streamers_update" ON streamers;
DROP POLICY IF EXISTS "streamers_delete" ON streamers;
DROP POLICY IF EXISTS "recaps_select"    ON recaps;
DROP POLICY IF EXISTS "recaps_insert"    ON recaps;
DROP POLICY IF EXISTS "recaps_update"    ON recaps;
DROP POLICY IF EXISTS "recaps_delete"    ON recaps;
DROP POLICY IF EXISTS "work_logs_select" ON work_logs;
DROP POLICY IF EXISTS "work_logs_insert" ON work_logs;
DROP POLICY IF EXISTS "work_logs_update" ON work_logs;
DROP POLICY IF EXISTS "work_logs_delete" ON work_logs;
DROP POLICY IF EXISTS "config_select"    ON config;
DROP POLICY IF EXISTS "config_insert"    ON config;
DROP POLICY IF EXISTS "config_update"    ON config;
DROP POLICY IF EXISTS "config_delete"    ON config;
DROP POLICY IF EXISTS "pol_sessions_self" ON sessions;

-- 重建策略（每个操作独立，用 is_auth()）
CREATE POLICY "scripts_sel" ON scripts FOR SELECT USING (is_auth());
CREATE POLICY "scripts_ins" ON scripts FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "scripts_upd" ON scripts FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "scripts_del" ON scripts FOR DELETE USING (is_auth());

CREATE POLICY "lighting_sel" ON lighting FOR SELECT USING (is_auth());
CREATE POLICY "lighting_ins" ON lighting FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "lighting_upd" ON lighting FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "lighting_del" ON lighting FOR DELETE USING (is_auth());

CREATE POLICY "streamers_sel" ON streamers FOR SELECT USING (is_auth());
CREATE POLICY "streamers_ins" ON streamers FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "streamers_upd" ON streamers FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "streamers_del" ON streamers FOR DELETE USING (is_auth());

CREATE POLICY "recaps_sel" ON recaps FOR SELECT USING (is_auth());
CREATE POLICY "recaps_ins" ON recaps FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "recaps_upd" ON recaps FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "recaps_del" ON recaps FOR DELETE USING (is_auth());

CREATE POLICY "work_logs_sel" ON work_logs FOR SELECT USING (is_auth());
CREATE POLICY "work_logs_ins" ON work_logs FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "work_logs_upd" ON work_logs FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "work_logs_del" ON work_logs FOR DELETE USING (is_auth());

CREATE POLICY "config_sel" ON config FOR SELECT USING (is_auth());
CREATE POLICY "config_ins" ON config FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "config_upd" ON config FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "config_del" ON config FOR DELETE USING (is_auth());

-- sessions：允许本人读删
CREATE POLICY "sessions_sel" ON sessions FOR SELECT USING (token = auth_token());
CREATE POLICY "sessions_del" ON sessions FOR DELETE USING (token = auth_token());
