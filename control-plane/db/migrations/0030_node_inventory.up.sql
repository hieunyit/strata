ALTER TABLE nodes ADD COLUMN inventory jsonb NOT NULL DEFAULT '{}';
ALTER TABLE nodes ADD COLUMN inventory_at timestamptz;
