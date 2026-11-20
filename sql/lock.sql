-- Site and page locks for the blog.
-- Run once in Supabase: SQL Editor → New query → paste all of this → Run.
-- Safe to run again; it replaces what it made before.
--
-- Scopes: 'site' (everything), and one per menu page:
--   'home' (check / home page), 'post' (e4), 'log' (e5), 'memo' (f4), 'line' (exf4), 'gallery' (?!)
-- Modes: 'open', 'private' (only you, logged in), 'password'.
-- Passwords are stored hashed (bcrypt) and never leave the database.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.lock_cfg(
  scope text primary key,
  mode  text not null default 'open' check (mode in ('open','private','password')),
  pw    text
);
alter table public.lock_cfg enable row level security;   -- no policies: nobody reads it directly

-- the mode of a scope ('open' when never set)
create or replace function public.lock_mode(p_scope text)
returns text language sql stable security definer set search_path = public as $$
  select coalesce((select mode from public.lock_cfg where scope = p_scope), 'open')
$$;

-- may this request see the scope? (open; logged in; or the right password)
create or replace function public.lock_ok(p_scope text, p_pw text default null)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select case coalesce(c.mode, 'open')
           when 'open'    then true
           when 'private' then auth.role() = 'authenticated'
           else auth.role() = 'authenticated'
                or (p_pw is not null and c.pw is not null and c.pw = crypt(p_pw, c.pw))
         end
  from (select 1) x left join public.lock_cfg c on c.scope = p_scope
$$;

-- what is locked (modes only, no passwords) — the site reads this to know what to ask for
create or replace function public.lock_info()
returns table(scope text, mode text) language sql stable security definer set search_path = public as $$
  select scope, mode from public.lock_cfg
$$;

-- change a lock (logged in only). An empty password keeps the old one.
create or replace function public.lock_set(p_scope text, p_mode text, p_pw text default null)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if auth.role() <> 'authenticated' then raise exception 'not allowed'; end if;
  if p_scope not in ('site','home','post','log','memo','line','gallery') then raise exception 'unknown scope %', p_scope; end if;
  if p_mode not in ('open','private','password') then raise exception 'unknown mode %', p_mode; end if;
  insert into public.lock_cfg(scope, mode, pw)
  values (p_scope, p_mode, case when coalesce(p_pw, '') <> '' then crypt(p_pw, gen_salt('bf')) end)
  on conflict (scope) do update set mode = excluded.mode, pw = coalesce(excluded.pw, public.lock_cfg.pw);
  if p_mode = 'password' and (select pw from public.lock_cfg where scope = p_scope) is null then
    raise exception 'a password is needed for %', p_scope;
  end if;
end $$;

-- the public feed now leaves out everything under a lock
create or replace view public.feed as
  select id, kind, title,
         case when visibility = 'locked' then null::text else body end as body,
         case when visibility = 'locked' then '{}'::jsonb else meta end as meta,
         tags, visibility, created_at
  from public.items
  where visibility = any (array['public','locked'])
    and public.lock_mode('site') = 'open'
    and public.lock_mode(kind) = 'open';

-- the same feed for visitors who typed passwords: {"site":"…","post":"…",…}
create or replace function public.feed_open(p_pw jsonb default '{}'::jsonb)
returns setof public.feed language sql stable security definer set search_path = public, extensions as $$
  select i.id, i.kind, i.title,
         case when i.visibility = 'locked' then null::text else i.body end,
         case when i.visibility = 'locked' then '{}'::jsonb else i.meta end,
         i.tags, i.visibility, i.created_at
  from public.items i
  where i.visibility in ('public','locked')
    and public.lock_ok('site', p_pw->>'site')
    and public.lock_ok(i.kind, p_pw->>i.kind)
$$;

-- home settings (header image, layout, jukebox, the home game and chat):
-- hidden from the public table read while the site or the home page is locked,
-- and given out here instead — without the home game/chat ('live') unless home is unlocked
drop policy if exists "settings read" on public.settings;
create policy "settings read" on public.settings for select to public
  using (key <> 'home' or (public.lock_mode('site') = 'open' and public.lock_mode('home') = 'open'));

create or replace function public.home_get(p_pw jsonb default '{}'::jsonb)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select case when not public.lock_ok('site', p_pw->>'site') then null
              when public.lock_ok('home', p_pw->>'home') then s.value
              else s.value - 'live' end
  from public.settings s where s.key = 'home'
$$;

grant execute on function public.lock_mode(text), public.lock_ok(text, text), public.lock_info(),
  public.feed_open(jsonb), public.home_get(jsonb) to anon, authenticated;
grant execute on function public.lock_set(text, text, text) to authenticated;
revoke execute on function public.lock_set(text, text, text) from anon;
grant select on public.feed to anon, authenticated;
