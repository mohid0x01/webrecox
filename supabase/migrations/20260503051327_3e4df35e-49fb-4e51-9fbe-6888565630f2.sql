CREATE TABLE public.shared_views (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  share_id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL DEFAULT 'recon',
  target_domain TEXT,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  view_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_shared_views_share_id ON public.shared_views(share_id);
CREATE INDEX idx_shared_views_kind ON public.shared_views(kind);

ALTER TABLE public.shared_views ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can create shared views"
  ON public.shared_views FOR INSERT TO public WITH CHECK (true);

CREATE POLICY "Anyone can view shared views"
  ON public.shared_views FOR SELECT TO public USING (true);

CREATE POLICY "Anyone can update view count"
  ON public.shared_views FOR UPDATE TO public USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

CREATE TRIGGER shared_views_updated_at
  BEFORE UPDATE ON public.shared_views
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();