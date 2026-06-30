-- ============================================
-- 紧急修复：RLS 写入漏洞
-- 在 Supabase SQL Editor 中运行
-- ============================================

-- 删除旧策略（只有 USING，缺 WITH CHECK）
DROP POLICY IF EXISTS "pol_scripts"   ON scripts;
DROP POLICY IF EXISTS "pol_lighting"  ON lighting;
DROP POLICY IF EXISTS "pol_streamers" ON streamers;
DROP POLICY IF EXISTS "pol_recaps"    ON recaps;
DROP POLICY IF EXISTS "pol_work_logs" ON work_logs;
DROP POLICY IF EXISTS "pol_config"    ON config;

-- 重建策略（USING + WITH CHECK）
CREATE POLICY "pol_scripts"   ON scripts   FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_lighting"  ON lighting  FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_streamers" ON streamers FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_recaps"    ON recaps    FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_work_logs" ON work_logs FOR ALL USING (is_auth()) WITH CHECK (is_auth());
CREATE POLICY "pol_config"    ON config    FOR ALL USING (is_auth()) WITH CHECK (is_auth());
