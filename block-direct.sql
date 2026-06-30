-- ============================================
-- 最后防线：RLS 阻止直接表访问
-- RPC 函数（SECURITY DEFINER）自动绕过
-- ============================================

ALTER TABLE scripts   ENABLE ROW LEVEL SECURITY;
ALTER TABLE lighting  ENABLE ROW LEVEL SECURITY;
ALTER TABLE streamers ENABLE ROW LEVEL SECURITY;
ALTER TABLE recaps    ENABLE ROW LEVEL SECURITY;
ALTER TABLE work_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE config    ENABLE ROW LEVEL SECURITY;

CREATE POLICY "block_scripts"   ON scripts   FOR ALL USING (false);
CREATE POLICY "block_lighting"  ON lighting  FOR ALL USING (false);
CREATE POLICY "block_streamers" ON streamers FOR ALL USING (false);
CREATE POLICY "block_recaps"    ON recaps    FOR ALL USING (false);
CREATE POLICY "block_work_logs" ON work_logs FOR ALL USING (false);
CREATE POLICY "block_config"    ON config    FOR ALL USING (false);
