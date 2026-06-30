-- 诊断：检查 RLS 是否真的启用了
SELECT
  schemaname || '.' || tablename AS table_name,
  row_level_security AS rls_enabled
FROM pg_tables
WHERE tablename IN ('scripts', 'lighting', 'streamers', 'recaps', 'work_logs', 'config', 'sessions')
AND schemaname = 'public';
