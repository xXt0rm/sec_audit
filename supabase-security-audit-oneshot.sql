-- ============================================================================
-- Auditoría de seguridad de Supabase — versión "de un solo tiro" (SOLO LECTURA)
-- ----------------------------------------------------------------------------
-- El SQL Editor de Supabase, al ejecutar varias sentencias, solo muestra el
-- resultado de la ÚLTIMA. Esta versión agrega TODO en un único resultado JSON,
-- en una sola celda, fácil de copiar y pegar de vuelta.
--
-- Uso: SQL Editor del proyecto de PRODUCCIÓN > New query > pega esto > Run.
-- Copia la celda "audit" (es texto JSON) y mándamela.
-- No modifica nada: solo SELECT contra catálogos del sistema.
-- ============================================================================
with
rls as (
  select jsonb_agg(jsonb_build_object(
    'table', c.relname, 'rls_enabled', c.relrowsecurity, 'rls_forced', c.relforcerowsecurity
  ) order by c.relrowsecurity, c.relname) as v
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where c.relkind = 'r' and n.nspname = 'public'
),
no_policy as (
  select jsonb_agg(c.relname order by c.relname) as v
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where c.relkind = 'r' and n.nspname = 'public' and c.relrowsecurity = true
    and not exists (select 1 from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname)
),
policies as (
  select jsonb_agg(jsonb_build_object(
    'table', tablename, 'policy', policyname, 'permissive', permissive,
    'roles', roles, 'cmd', cmd, 'using', qual, 'with_check', with_check
  ) order by tablename, cmd, policyname) as v
  from pg_policies where schemaname = 'public'
),
grants as (
  select jsonb_agg(jsonb_build_object(
    'table', table_name, 'grantee', grantee, 'privileges', privs
  ) order by grantee, table_name) as v
  from (
    select table_name, grantee, string_agg(privilege_type, ', ' order by privilege_type) as privs
    from information_schema.role_table_grants
    where grantee in ('anon', 'authenticated') and table_schema = 'public'
    group by table_name, grantee
  ) g
),
secdef_funcs as (
  select jsonb_agg(jsonb_build_object(
    'function', p.proname, 'config', coalesce(array_to_string(p.proconfig, ', '), '(sin search_path)')
  ) order by p.proname) as v
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.prosecdef = true
),
secdef_views as (
  select jsonb_agg(jsonb_build_object(
    'view', c.relname, 'options', coalesce(array_to_string(c.reloptions, ', '), '(ninguna)')
  ) order by c.relname) as v
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where c.relkind = 'v' and n.nspname = 'public'
    and not exists (select 1 from unnest(coalesce(c.reloptions, array[]::text[])) opt where opt ilike 'security_invoker=%')
),
exts as (
  select jsonb_agg(e.extname order by e.extname) as v
  from pg_extension e join pg_namespace n on n.oid = e.extnamespace where n.nspname = 'public'
)
select jsonb_pretty(jsonb_build_object(
  'rls_by_table',                (select v from rls),
  'rls_enabled_but_no_policy',   (select v from no_policy),
  'policies',                    (select v from policies),
  'anon_authenticated_grants',   (select v from grants),
  'security_definer_functions',  (select v from secdef_funcs),
  'non_security_invoker_views',  (select v from secdef_views),
  'extensions_in_public',        (select v from exts),
  'anon_can_read_auth_users',    (select has_table_privilege('anon', 'auth.users', 'SELECT'))
)) as audit;
