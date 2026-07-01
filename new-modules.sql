-- ============================================
-- 直播运营工作台 — 4个新模块
-- ============================================

-- 1. 大哥管理
CREATE TABLE IF NOT EXISTS vips (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  platform TEXT DEFAULT '',
  total_spent NUMERIC DEFAULT 0,
  preferences TEXT DEFAULT '',
  birthday TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. PK对手库
CREATE TABLE IF NOT EXISTS opponents (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  platform TEXT DEFAULT '',
  estimated_rank TEXT DEFAULT '',
  typical_style TEXT DEFAULT '',
  win_count BIGINT DEFAULT 0,
  loss_count BIGINT DEFAULT 0,
  strategy_notes TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. 排班表
CREATE TABLE IF NOT EXISTS schedules (
  id BIGSERIAL PRIMARY KEY,
  schedule_date TEXT NOT NULL,
  streamer TEXT NOT NULL,
  time_slot TEXT NOT NULL,
  status TEXT DEFAULT 'scheduled',
  notes TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- RLS 封锁
-- ============================================
ALTER TABLE vips      ENABLE ROW LEVEL SECURITY;
ALTER TABLE opponents ENABLE ROW LEVEL SECURITY;
ALTER TABLE schedules ENABLE ROW LEVEL SECURITY;

CREATE POLICY "block_vips"      ON vips      FOR ALL USING (false);
CREATE POLICY "block_opponents" ON opponents FOR ALL USING (false);
CREATE POLICY "block_schedules" ON schedules FOR ALL USING (false);

-- ============================================
-- RPC: 大哥管理
-- ============================================
CREATE OR REPLACE FUNCTION api_vips_list(tok TEXT)
RETURNS SETOF vips AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM vips ORDER BY total_spent DESC, id ASC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_vips_add(tok TEXT, name_ TEXT, platform_ TEXT, total_spent_ NUMERIC, preferences_ TEXT, birthday_ TEXT, notes_ TEXT)
RETURNS vips AS $$
DECLARE r vips;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO vips (name,platform,total_spent,preferences,birthday,notes)
VALUES (name_,platform_,total_spent_,preferences_,birthday_,notes_)
RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_vips_del(tok TEXT, id_ BIGINT)
RETURNS VOID AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM vips WHERE id = id_;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- RPC: PK对手库
-- ============================================
CREATE OR REPLACE FUNCTION api_opponents_list(tok TEXT)
RETURNS SETOF opponents AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM opponents ORDER BY name ASC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_opponents_add(tok TEXT, name_ TEXT, platform_ TEXT, estimated_rank_ TEXT, typical_style_ TEXT, win_count_ BIGINT, loss_count_ BIGINT, strategy_notes_ TEXT)
RETURNS opponents AS $$
DECLARE r opponents;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO opponents (name,platform,estimated_rank,typical_style,win_count,loss_count,strategy_notes)
VALUES (name_,platform_,estimated_rank_,typical_style_,win_count_,loss_count_,strategy_notes_)
RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_opponents_del(tok TEXT, id_ BIGINT)
RETURNS VOID AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM opponents WHERE id = id_;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- RPC: 排班表
-- ============================================
CREATE OR REPLACE FUNCTION api_schedules_list(tok TEXT)
RETURNS SETOF schedules AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
RETURN QUERY SELECT * FROM schedules ORDER BY schedule_date DESC, time_slot ASC;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_schedules_add(tok TEXT, schedule_date_ TEXT, streamer_ TEXT, time_slot_ TEXT, status_ TEXT, notes_ TEXT)
RETURNS schedules AS $$
DECLARE r schedules;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
INSERT INTO schedules (schedule_date,streamer,time_slot,status,notes)
VALUES (schedule_date_,streamer_,time_slot_,COALESCE(status_,'scheduled'),notes_)
RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_schedules_del(tok TEXT, id_ BIGINT)
RETURNS VOID AS $$
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
DELETE FROM schedules WHERE id = id_;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_schedules_status(tok TEXT, id_ BIGINT, status_ TEXT)
RETURNS schedules AS $$
DECLARE r schedules;
BEGIN IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
UPDATE schedules SET status = status_ WHERE id = id_ RETURNING * INTO r;
RETURN r;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- RPC: 收入面板（查询 recaps 表）
-- ============================================
CREATE OR REPLACE FUNCTION api_revenue_summary(tok TEXT, streamer_filter TEXT, start_date TEXT, end_date TEXT)
RETURNS TABLE(
  streamer TEXT,
  total_income NUMERIC,
  total_views BIGINT,
  avg_peak BIGINT,
  avg_stay NUMERIC,
  total_fans BIGINT,
  total_payers BIGINT,
  total_big_gift BIGINT,
  total_big_gift_amt NUMERIC,
  pk_total BIGINT,
  pk_wins BIGINT,
  recaps_count BIGINT,
  date_min TEXT,
  date_max TEXT
) AS $$
BEGIN
  IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
  RETURN QUERY
  SELECT
    r.streamer,
    COALESCE(SUM(r.income), 0)::NUMERIC,
    COALESCE(SUM(r.views), 0)::BIGINT,
    COALESCE(ROUND(AVG(r.peak)), 0)::BIGINT,
    COALESCE(ROUND(AVG(r.stay), 1), 0)::NUMERIC,
    COALESCE(SUM(r.fans), 0)::BIGINT,
    COALESCE(SUM(r.payers), 0)::BIGINT,
    COALESCE(SUM(r.big_gift), 0)::BIGINT,
    COALESCE(SUM(r.big_gift_amt), 0)::NUMERIC,
    COALESCE(SUM(r.pk_count), 0)::BIGINT,
    COALESCE(SUM(r.pk_win), 0)::BIGINT,
    COUNT(*)::BIGINT,
    MIN(r.date)::TEXT,
    MAX(r.date)::TEXT
  FROM recaps r
  WHERE (streamer_filter = '' OR r.streamer = streamer_filter)
    AND (start_date = '' OR r.date >= start_date)
    AND (end_date = '' OR r.date <= end_date)
  GROUP BY r.streamer
  ORDER BY total_income DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION api_revenue_detail(tok TEXT, streamer_filter TEXT, start_date TEXT, end_date TEXT)
RETURNS TABLE(
  date TEXT,
  streamer TEXT,
  income NUMERIC,
  views BIGINT,
  peak BIGINT,
  stay BIGINT,
  fans BIGINT,
  payers BIGINT
) AS $$
BEGIN
  IF NOT check_token(tok) THEN RAISE 'unauthorized'; END IF;
  RETURN QUERY
  SELECT r.date, r.streamer, r.income, r.views, r.peak, r.stay, r.fans, r.payers
  FROM recaps r
  WHERE (streamer_filter = '' OR r.streamer = streamer_filter)
    AND (start_date = '' OR r.date >= start_date)
    AND (end_date = '' OR r.date <= end_date)
  ORDER BY r.date ASC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
