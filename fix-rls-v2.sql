-- ============================================
-- RLS 修复 v2：改用显式操作类型策略
-- ============================================

-- 删除所有旧策略
DROP POLICY IF EXISTS "pol_scripts"   ON scripts;
DROP POLICY IF EXISTS "pol_lighting"  ON lighting;
DROP POLICY IF EXISTS "pol_streamers" ON streamers;
DROP POLICY IF EXISTS "pol_recaps"    ON recaps;
DROP POLICY IF EXISTS "pol_work_logs" ON work_logs;
DROP POLICY IF EXISTS "pol_config"    ON config;

-- 诊断：创建调试函数
CREATE OR REPLACE FUNCTION debug_headers()
RETURNS TEXT AS $$
BEGIN
  RETURN COALESCE(current_setting('request.headers', true), 'NO HEADERS SET');
END;
$$ LANGUAGE plpgsql STABLE;

-- 修复 auth_token() — 更健壮的实现
CREATE OR REPLACE FUNCTION auth_token()
RETURNS TEXT AS $$
DECLARE
  headers_text TEXT;
BEGIN
  headers_text := current_setting('request.headers', true);
  IF headers_text IS NULL OR headers_text = '' THEN
    RETURN '';
  END IF;
  RETURN COALESCE(headers_text::json->>'x-session-token', '');
EXCEPTION WHEN OTHERS THEN
  RETURN '';
END;
$$ LANGUAGE plpgsql STABLE;

-- 加固 is_auth() — 显式判空
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

-- 每个表分别建 SELECT/INSERT/UPDATE/DELETE 策略
CREATE POLICY "scripts_select" ON scripts FOR SELECT USING (is_auth());
CREATE POLICY "scripts_insert" ON scripts FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "scripts_update" ON scripts FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "scripts_delete" ON scripts FOR DELETE USING (is_auth());

CREATE POLICY "lighting_select" ON lighting FOR SELECT USING (is_auth());
CREATE POLICY "lighting_insert" ON lighting FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "lighting_update" ON lighting FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "lighting_delete" ON lighting FOR DELETE USING (is_auth());

CREATE POLICY "streamers_select" ON streamers FOR SELECT USING (is_auth());
CREATE POLICY "streamers_insert" ON streamers FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "streamers_update" ON streamers FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "streamers_delete" ON streamers FOR DELETE USING (is_auth());

CREATE POLICY "recaps_select" ON recaps FOR SELECT USING (is_auth());
CREATE POLICY "recaps_insert" ON recaps FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "recaps_update" ON recaps FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "recaps_delete" ON recaps FOR DELETE USING (is_auth());

CREATE POLICY "work_logs_select" ON work_logs FOR SELECT USING (is_auth());
CREATE POLICY "work_logs_insert" ON work_logs FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "work_logs_update" ON work_logs FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "work_logs_delete" ON work_logs FOR DELETE USING (is_auth());

CREATE POLICY "config_select" ON config FOR SELECT USING (is_auth());
CREATE POLICY "config_insert" ON config FOR INSERT WITH CHECK (is_auth());
CREATE POLICY "config_update" ON config FOR UPDATE USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "config_delete" ON config FOR DELETE USING (is_auth());
