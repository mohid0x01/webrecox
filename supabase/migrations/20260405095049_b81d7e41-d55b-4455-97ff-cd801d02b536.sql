
CREATE TABLE public.scan_results (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  domain TEXT NOT NULL,
  scan_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  scan_type TEXT NOT NULL DEFAULT 'full',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_results_domain ON public.scan_results(domain);
CREATE INDEX idx_scan_results_created_at ON public.scan_results(created_at DESC);

ALTER TABLE public.scan_results ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view scan results"
ON public.scan_results FOR SELECT
USING (true);

CREATE POLICY "Anyone can insert scan results"
ON public.scan_results FOR INSERT
WITH CHECK (true);

CREATE POLICY "Anyone can update scan results"
ON public.scan_results FOR UPDATE
USING (true);
