-- ============================================================================
-- Auditoría de seguridad de Supabase — SOLO LECTURA
-- ----------------------------------------------------------------------------
-- Ejecuta este script en el SQL Editor de tu proyecto de PRODUCCIÓN.
-- Son únicamente consultas SELECT contra catálogos del sistema: NO modifica
-- datos, NO crea nada, NO es invasivo. Audita tu configuración REAL (RLS,
-- privilegios, funciones), que es justo lo que un Supabase de prueba no replica.
--
-- Lee los resultados de arriba a abajo. Cada bloque dice qué esperar.
-- ============================================================================


-- 1) RLS por tabla en el esquema público -------------------------------------
--    relrowsecurity = RLS activado.  relforcerowsecurity = forzado al dueño.
--    ESPERADO: rls_enabled = true en TODAS las tablas.
--    CRÍTICO:  cualquier fila con rls_enabled = false en un esquema expuesto.
select
  n.nspname               as schema,
  c.relname               as table,
  c.relrowsecurity        as rls_enabled,
  c.relforcerowsecurity   as rls_forced
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'r'
  and n.nspname in ('public')          -- añade aquí otros esquemas expuestos a la API
order by c.relrowsecurity asc, c.relname;


-- 2) Tablas con RLS activado pero SIN ninguna política -----------------------
--    RLS sin políticas = deny-all (nadie accede). Suele ser un olvido.
--    Revisa que sea intencional.
select
  c.relname as table_without_policies
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'r'
  and n.nspname = 'public'
  and c.relrowsecurity = true
  and not exists (
    select 1 from pg_policies p
    where p.schemaname = 'public' and p.tablename = c.relname
  )
order by c.relname;


-- 3) Todas las políticas RLS, con sus expresiones -----------------------------
--    Revisa manualmente USING (lectura) y WITH CHECK (escritura).
--    Presta atención a roles {anon} y {public}.
select
  tablename,
  policyname,
  permissive,
  roles,
  cmd                      as command,
  qual                     as using_expr,
  with_check               as with_check_expr
from pg_policies
where schemaname = 'public'
order by tablename, cmd, policyname;


-- 4) Políticas potencialmente peligrosas -------------------------------------
--    Señala políticas abiertas (USING true) o que dan acceso a anon/public.
--    Para `products` lo correcto es: anon solo SELECT con published = true.
--    Para cualquier tabla con datos personales o de pedidos: anon sin acceso.
select
  tablename,
  policyname,
  roles,
  cmd as command,
  qual as using_expr,
  with_check as with_check_expr,
  case
    when (qual is null or btrim(qual) in ('true','(true)'))
         and cmd in ('SELECT','ALL') then 'ABIERTA A LECTURA'
    when (with_check is null or btrim(with_check) in ('true','(true)'))
         and cmd in ('INSERT','UPDATE','ALL') then 'ABIERTA A ESCRITURA'
    else 'revisar'
  end as flag
from pg_policies
where schemaname = 'public'
  and (
    roles::text[] && array['anon','public']
    or qual is null or btrim(qual) in ('true','(true)')
    or with_check is null
  )
order by tablename, policyname;


-- 5) Privilegios de tabla concedidos a anon / authenticated ------------------
--    anon = cualquier visitante no autenticado (clave anon pública).
--    PELIGRO: anon con INSERT/UPDATE/DELETE, o con SELECT sobre tablas de PII.
select
  table_schema  as schema,
  table_name    as table,
  grantee,
  string_agg(privilege_type, ', ' order by privilege_type) as privileges
from information_schema.role_table_grants
where grantee in ('anon', 'authenticated')
  and table_schema in ('public')
group by table_schema, table_name, grantee
order by grantee, table_name;


-- 6) Funciones SECURITY DEFINER y su search_path -----------------------------
--    SECURITY DEFINER corre con permisos del dueño (puede saltar RLS).
--    RIESGO: search_path mutable → secuestro de search_path.
--    ESPERADO: cada una fija search_path (p. ej. 'search_path=public' o '').
select
  n.nspname as schema,
  p.proname as function,
  p.prosecdef as security_definer,
  coalesce(array_to_string(p.proconfig, ', '), '(sin set search_path)') as config
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.prosecdef = true
order by p.proname;


-- 7) Vistas que NO son security_invoker --------------------------------------
--    En Postgres 15+ una vista sin `security_invoker=on` corre como su dueño
--    y puede SALTAR la RLS de las tablas base. Supabase lo marca como lint
--    "Security Definer View". ESPERADO: idealmente ninguna, o revisadas.
select
  n.nspname as schema,
  c.relname as view,
  coalesce(array_to_string(c.reloptions, ', '), '(sin opciones)') as options
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'v'
  and n.nspname = 'public'
  and not exists (
    select 1 from unnest(coalesce(c.reloptions, array[]::text[])) opt
    where opt ilike 'security_invoker=%'
  )
order by c.relname;


-- 8) Extensiones instaladas en el esquema público ----------------------------
--    Buena práctica: extensiones en un esquema `extensions`, no en `public`.
select e.extname as extension, n.nspname as schema
from pg_extension e
join pg_namespace n on n.oid = e.extnamespace
where n.nspname = 'public'
order by e.extname;


-- 9) Permisos de USO de esquema para anon / authenticated / public -----------
--    Revisa si `public` (todos) tiene USAGE/CREATE amplio sobre el esquema.
select
  n.nspname as schema,
  r.rolname as role,
  has_schema_privilege(r.rolname, n.nspname, 'USAGE')  as usage,
  has_schema_privilege(r.rolname, n.nspname, 'CREATE') as create
from pg_namespace n
cross join (select rolname from pg_roles where rolname in ('anon','authenticated','public')) r
where n.nspname = 'public'
order by r.rolname;


-- 10) Comprobación: ¿puede anon leer auth.users? -----------------------------
--     ESPERADO: false. Si fuese true, los datos de cuentas estarían expuestos.
select
  has_table_privilege('anon', 'auth.users', 'SELECT') as anon_can_read_auth_users;


-- ============================================================================
-- CHECKLIST MANUAL (no consultable por SQL — revísalo en el panel de Supabase)
-- ----------------------------------------------------------------------------
-- [ ] API > Exposed schemas: solo los esquemas que realmente sirves (public).
-- [ ] Auth > URL Configuration: Redirect URLs en allowlist estricta
--     (evita open-redirect en /callback). Site URL correcto.
-- [ ] Auth: confirmación de email activada; expiración de JWT razonable;
--     proveedores OAuth solo los que uses.
-- [ ] Storage: buckets privados por defecto; políticas por bucket; nada
--     sensible en buckets públicos.
-- [ ] Edge Functions: verifican JWT / no exponen operaciones sin auth.
-- [ ] Database > Network Restrictions / allowed origins si aplica.
-- [ ] Service role key: nunca en el cliente ni en logs. Rótala si alguna vez
--     estuvo en un .env compartido o en logs de build.
-- [ ] Database functions con triggers: revisa las que insertan en public.* .
-- ============================================================================
