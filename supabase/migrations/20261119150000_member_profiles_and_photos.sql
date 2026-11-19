-- Stage 3 authenticated profiles and private profile-photo storage.
CREATE TABLE public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name text NOT NULL
    CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 50),
  country text NOT NULL,
  city text,
  gender text
    CHECK (gender IN ('Male', 'Female', 'Prefer not to say')),
  bio text
    CHECK (bio IS NULL OR char_length(bio) <= 300),
  avatar_path text,
  interests text[] NOT NULL DEFAULT '{}'::text[]
    CHECK (cardinality(interests) <= 20),
  account_type text NOT NULL
    CHECK (account_type IN ('user', 'creator')),
  onboarding_complete boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT profiles_avatar_owner_path CHECK (
    avatar_path IS NULL
    OR split_part(avatar_path, '/', 1) = id::text
  )
);

CREATE TABLE public.profile_private (
  id uuid PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
  first_name text NOT NULL
    CHECK (char_length(btrim(first_name)) BETWEEN 1 AND 80),
  last_name text NOT NULL
    CHECK (char_length(btrim(last_name)) BETWEEN 1 AND 80),
  date_of_birth date NOT NULL
);

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profile_private ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.profiles, public.profile_private
  FROM PUBLIC, anon;

GRANT SELECT, INSERT, UPDATE ON TABLE public.profiles TO authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.profile_private TO authenticated;

CREATE POLICY profiles_read_authenticated
ON public.profiles
FOR SELECT TO authenticated
USING (
  auth.uid() IS NOT NULL
  AND (id = auth.uid() OR onboarding_complete)
);

CREATE POLICY profiles_insert_owner
ON public.profiles
FOR INSERT TO authenticated
WITH CHECK (id = auth.uid());

CREATE POLICY profiles_update_owner
ON public.profiles
FOR UPDATE TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());

CREATE POLICY profile_private_read_owner
ON public.profile_private
FOR SELECT TO authenticated
USING (id = auth.uid());

CREATE POLICY profile_private_insert_owner
ON public.profile_private
FOR INSERT TO authenticated
WITH CHECK (id = auth.uid());

CREATE POLICY profile_private_update_owner
ON public.profile_private
FOR UPDATE TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());

CREATE FUNCTION public.enforce_profile_adult_age()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  IF NEW.date_of_birth > (CURRENT_DATE - INTERVAL '18 years')::date THEN
    RAISE EXCEPTION 'Profile owner must be at least 18 years old'
      USING ERRCODE = 'check_violation';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER profile_private_require_adult
BEFORE INSERT OR UPDATE OF date_of_birth
ON public.profile_private
FOR EACH ROW
EXECUTE FUNCTION public.enforce_profile_adult_age();

CREATE FUNCTION public.set_profile_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  NEW.updated_at = pg_catalog.now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER profiles_set_updated_at
BEFORE UPDATE ON public.profiles
FOR EACH ROW
EXECUTE FUNCTION public.set_profile_updated_at();

CREATE FUNCTION public.profile_age(p_profile_id uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXTRACT(
    YEAR FROM pg_catalog.age(CURRENT_DATE, pp.date_of_birth)
  )::integer
  FROM public.profile_private AS pp
  WHERE pp.id = p_profile_id
    AND auth.uid() IS NOT NULL;
$$;

REVOKE ALL ON FUNCTION public.profile_age(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.profile_age(uuid) TO authenticated;

CREATE VIEW public.profile_cards
WITH (security_invoker = true)
AS
SELECT
  p.id,
  p.display_name,
  p.country,
  p.city,
  p.gender,
  p.bio,
  p.avatar_path,
  p.interests,
  p.account_type,
  public.profile_age(p.id) AS age
FROM public.profiles AS p
WHERE p.onboarding_complete
  AND public.profile_age(p.id) IS NOT NULL;

REVOKE ALL ON public.profile_cards FROM PUBLIC, anon;
GRANT SELECT ON public.profile_cards TO authenticated;

INSERT INTO storage.buckets (
  id,
  name,
  public,
  file_size_limit,
  allowed_mime_types
)
VALUES (
  'profile-photos',
  'profile-photos',
  false,
  5242880,
  ARRAY['image/jpeg', 'image/png', 'image/webp']::text[]
)
ON CONFLICT (id) DO UPDATE
SET
  name = EXCLUDED.name,
  public = false,
  file_size_limit = EXCLUDED.file_size_limit,
  allowed_mime_types = EXCLUDED.allowed_mime_types;

CREATE POLICY profile_photos_read_authenticated
ON storage.objects
FOR SELECT TO authenticated
USING (
  bucket_id = 'profile-photos'
  AND (
    (storage.foldername(name))[1] = (SELECT auth.uid()::text)
    OR EXISTS (
      SELECT 1
      FROM public.profiles AS p
      WHERE p.avatar_path = name
        AND p.onboarding_complete
    )
  )
);

CREATE POLICY profile_photos_limit_read
ON storage.objects
AS RESTRICTIVE
FOR SELECT TO authenticated
USING (
  bucket_id <> 'profile-photos'
  OR (
    auth.uid() IS NOT NULL
    AND (
      (storage.foldername(name))[1] = auth.uid()::text
      OR EXISTS (
        SELECT 1
        FROM public.profiles AS p
        WHERE p.avatar_path = name
          AND p.onboarding_complete
      )
    )
  )
);

CREATE POLICY profile_photos_deny_anon_read
ON storage.objects
AS RESTRICTIVE
FOR SELECT TO anon
USING (bucket_id <> 'profile-photos');

CREATE POLICY profile_photos_insert_owner
ON storage.objects
FOR INSERT TO authenticated
WITH CHECK (
  bucket_id = 'profile-photos'
  AND (storage.foldername(name))[1] = (SELECT auth.uid()::text)
);

CREATE POLICY profile_photos_limit_insert
ON storage.objects
AS RESTRICTIVE
FOR INSERT TO public
WITH CHECK (
  bucket_id <> 'profile-photos'
  OR (
    auth.uid() IS NOT NULL
    AND (storage.foldername(name))[1] = auth.uid()::text
  )
);

CREATE POLICY profile_photos_update_owner
ON storage.objects
FOR UPDATE TO authenticated
USING (
  bucket_id = 'profile-photos'
  AND (storage.foldername(name))[1] = (SELECT auth.uid()::text)
)
WITH CHECK (
  bucket_id = 'profile-photos'
  AND (storage.foldername(name))[1] = (SELECT auth.uid()::text)
);

CREATE POLICY profile_photos_limit_update
ON storage.objects
AS RESTRICTIVE
FOR UPDATE TO public
USING (
  bucket_id <> 'profile-photos'
  OR (
    auth.uid() IS NOT NULL
    AND (storage.foldername(name))[1] = auth.uid()::text
  )
)
WITH CHECK (
  bucket_id <> 'profile-photos'
  OR (
    auth.uid() IS NOT NULL
    AND (storage.foldername(name))[1] = auth.uid()::text
  )
);

CREATE POLICY profile_photos_delete_owner
ON storage.objects
FOR DELETE TO authenticated
USING (
  bucket_id = 'profile-photos'
  AND (storage.foldername(name))[1] = (SELECT auth.uid()::text)
);

CREATE POLICY profile_photos_limit_delete
ON storage.objects
AS RESTRICTIVE
FOR DELETE TO public
USING (
  bucket_id <> 'profile-photos'
  OR (
    auth.uid() IS NOT NULL
    AND (storage.foldername(name))[1] = auth.uid()::text
  )
);
