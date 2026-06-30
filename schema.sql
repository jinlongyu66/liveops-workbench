-- ============================================
-- 直播运营工作台 - 安全加固 SQL
-- 在 Supabase SQL Editor 中运行
-- ============================================

-- 0. 启用 pgcrypto（密码哈希）
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================
-- 1. 密码哈希化
-- ============================================
UPDATE config SET value = crypt('admin123', gen_salt('bf')) WHERE key = 'password';

-- ============================================
-- 2. 会话表
-- ============================================
CREATE TABLE IF NOT EXISTS sessions (
  id BIGSERIAL PRIMARY KEY,
  token TEXT NOT NULL UNIQUE DEFAULT gen_random_uuid()::text,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '24 hours')
);

-- ============================================
-- 3. 认证辅助函数
-- ============================================

-- 从请求头提取 token
CREATE OR REPLACE FUNCTION auth_token()
RETURNS TEXT AS $$
BEGIN
  RETURN COALESCE(
    (current_setting('request.headers', true)::json->>'x-session-token')::text,
    ''
  );
EXCEPTION WHEN OTHERS THEN
  RETURN '';
END;
$$ LANGUAGE plpgsql STABLE;

-- 验证是否已认证（SECURITY DEFINER 绕过 RLS 读取 sessions）
CREATE OR REPLACE FUNCTION is_auth()
RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS(
    SELECT 1 FROM sessions
    WHERE token = auth_token()
    AND expires_at > NOW()
  );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================
-- 4. RPC 函数（登录/改密/登出）
-- ============================================

-- 登录：验证密码，返回 token
CREATE OR REPLACE FUNCTION login(password_text TEXT)
RETURNS TEXT AS $$
DECLARE
  stored_hash TEXT;
  new_token TEXT;
BEGIN
  SELECT value INTO stored_hash FROM config WHERE key = 'password';
  IF stored_hash IS NULL OR stored_hash != crypt(password_text, stored_hash) THEN
    RETURN NULL;
  END IF;
  DELETE FROM sessions WHERE expires_at < NOW();
  new_token := gen_random_uuid()::text;
  INSERT INTO sessions (token) VALUES (new_token);
  RETURN new_token;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 修改密码
CREATE OR REPLACE FUNCTION change_pw(new_password TEXT)
RETURNS BOOLEAN AS $$
BEGIN
  IF NOT is_auth() THEN
    RETURN false;
  END IF;
  UPDATE config SET value = crypt(new_password, gen_salt('bf')) WHERE key = 'password';
  RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 登出
CREATE OR REPLACE FUNCTION logout_fn()
RETURNS void AS $$
BEGIN
  DELETE FROM sessions WHERE token = auth_token();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- 5. 启用 RLS
-- ============================================
ALTER TABLE config ENABLE ROW LEVEL SECURITY;
ALTER TABLE scripts ENABLE ROW LEVEL SECURITY;
ALTER TABLE lighting ENABLE ROW LEVEL SECURITY;
ALTER TABLE streamers ENABLE ROW LEVEL SECURITY;
ALTER TABLE recaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- ============================================
-- 6. RLS 策略 — 所有表通过 is_auth() 控制
-- ============================================
CREATE POLICY "pol_scripts"   ON scripts   FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_lighting"  ON lighting  FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_streamers" ON streamers FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_recaps"    ON recaps    FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_work_logs" ON work_logs FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_config"    ON config    FOR ALL USING (is_auth()) WITH CHECK (is_auth());

-- sessions 表：允许 is_auth() 函数读取（SECURITY DEFINER 自动绕过）
-- 但也要允许本人删除自己的 token
CREATE POLICY "pol_sessions_self" ON sessions
  FOR DELETE
  USING (token = auth_token());

-- ============================================
-- 7. 定时清理过期会话（可选）
-- 在 Supabase → Database → Extensions 启用 pg_cron 后可用
-- SELECT cron.schedule('cleanup-sessions', '0 * * * *', 'DELETE FROM sessions WHERE expires_at < NOW()');
-- ============================================
