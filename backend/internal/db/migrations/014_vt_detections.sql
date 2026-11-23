-- Which VirusTotal engines flagged an IP (engine, category, result), so alerts can name them
-- instead of only giving a count. Filled on the next VirusTotal lookup of each address.
ALTER TABLE ip_info ADD COLUMN IF NOT EXISTS vt_detections jsonb;
