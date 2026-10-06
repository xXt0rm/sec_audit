# Auditoría de Supabase — resultados e interpretación

**Fecha:** 2026-10-06
**Fuente:** Security Advisor de Supabase (producción) + tipos generados del repo.

## Veredicto

**Buena noticia en conjunto.** **0 errores.** La arquitectura de datos es correcta: los datos
sensibles están aislados en un esquema **`private`** con RLS activada, separados del esquema **`public`**
que expone la API, el cual solo sirve la tabla `products` (lectura de publicados). Hay **un único punto
real que arreglar**: una función `SECURITY DEFINER` en `public` ejecutable por visitantes anónimos.

Resumen del Advisor:

| Nivel | Cantidad | Qué es |
|-------|----------|--------|
| Errors | 0 | — |
| Warnings | 2 | La misma función `public.membership_batch_status()` (ver Hallazgo 1) |
| Info (suggestions) | 31 | Tablas `private.*` con RLS activada y sin política (ver Hallazgo 2) |

## Lo que está bien (y es importante)

- **Modelo de datos bien separado.** El esquema expuesto a la API (`public`) contiene esencialmente solo
  `products`. Todo lo sensible (clientes, comercio, membresías, comunidad, pagos, PII como
  `guest_email_alerts` o `guest_resource_contacts`) vive en el esquema **`private`**, que por convención
  no se expone por la API de PostgREST.
- **`private.*` con RLS activada y sin políticas = deny-all por la API.** Es *fail-closed*: nadie accede a
  esas tablas con la clave anónima. Es el estado seguro por defecto.
- **Ninguna tabla con RLS desactivada en un esquema expuesto.** Ese es el fallo peligroso de verdad, y
  **no lo tienes**. Por eso hay 0 errores.

## Hallazgo 1 (acción) — Función SECURITY DEFINER ejecutable por anónimos · Media

`public.membership_batch_status()`:

- Está en **`public`**, que **sí** se expone a la API, así que es invocable como RPC en
  `POST /rest/v1/rpc/membership_batch_status` por quien tenga permiso.
- Es **SECURITY DEFINER**: corre con los permisos de su dueño, así que puede leer/escribir las tablas
  `private` **saltándose la RLS**.
- Tiene **EXECUTE para `public`/`anon`** (cualquiera, sin login) y para `authenticated`.

**Riesgo:** según lo que haga la función, un visitante no autenticado podría invocar lógica privilegiada o
extraer datos de `private`. **Causa raíz habitual:** al crear una función, Postgres concede `EXECUTE` a
`PUBLIC` por defecto; es fácil que se quedara así sin querer.

**Acción:**

1. **Revisa qué hace** (consulta de inspección abajo). Eso decide si es benigna o si filtra datos.
2. **Revoca `EXECUTE` a `PUBLIC`/`anon`.** Concede solo al rol que la necesite, o llámala **desde tu
   servidor con la `service_role` key**, que no pasa por estos grants.
3. **Fija el `search_path`** si no lo tiene (evita secuestro de search_path en funciones SECURITY DEFINER).

## Hallazgo 2 (informativo) — 31 tablas `private.*` con RLS sin política

Es el estado **seguro** (deny-all por la API), no un agujero. El Advisor lo marca como *Info* solo para
avisarte de que activaste RLS pero no creaste políticas, por si fue un olvido. Acciones:

- **Confirma en Settings > API > Exposed schemas** que `private` **NO** está expuesto (deben aparecer solo
  `public` y `graphql_public`). Esto es lo más importante de todo este bloque. No es consultable por SQL;
  se ve en el panel.
- **Define por tabla la vía de acceso prevista:** normalmente será la `service_role` desde tu servidor, o
  una función SECURITY DEFINER con su propia comprobación de autorización. Si algún rol debe acceder
  directo a alguna tabla, entonces sí añade una política explícita. Si no, déjalas en deny-all.

## Nota de alcance

El modelo de datos real (membresías, comercio, comunidad, pagos) es **mucho mayor** que el frontend
`mindupgrade-web` que audité, que solo usa `products`. Hay lógica de negocio en **funciones de base de
datos** que merece su propia revisión. `membership_batch_status` es la primera que aparece; conviene
revisar todas las funciones SECURITY DEFINER del esquema expuesto.

---

## Consultas de inspección (SOLO LECTURA)

### 1) Ver la función marcada: firma, retorno, seguridad, search_path y cuerpo

```sql
select
  n.nspname as schema,
  p.proname as function,
  pg_get_function_identity_arguments(p.oid) as args,
  pg_get_function_result(p.oid)             as returns,
  p.prosecdef                               as security_definer,
  coalesce(array_to_string(p.proconfig, ', '), '(sin search_path fijo)') as config,
  pg_get_functiondef(p.oid)                 as definition
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.proname = 'membership_batch_status';
```

### 2) Quién puede ejecutarla

```sql
select grantee, privilege_type
from information_schema.role_routine_grants
where routine_schema = 'public' and routine_name = 'membership_batch_status';
```

### 3) Todas las funciones SECURITY DEFINER del esquema expuesto (por si hay más)

```sql
select p.proname,
       pg_get_function_identity_arguments(p.oid) as args,
       coalesce(array_to_string(p.proconfig, ', '), '(sin search_path)') as config
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prosecdef = true
order by p.proname;
```

---

## Remediación propuesta (ejecutar cuando lo decidas, tras revisar el cuerpo)

Sustituye `(<ARGS>)` por la firma exacta que te dé la consulta 1 (p. ej. `(uuid)` o `()`):

```sql
-- 1) Quitar ejecución a todo el mundo, incluido anon:
revoke execute on function public.membership_batch_status(<ARGS>) from public, anon;

-- 2) (Opcional) concederla solo a usuarios autenticados, si tu app la necesita desde el cliente:
-- grant execute on function public.membership_batch_status(<ARGS>) to authenticated;

-- 3) Fijar search_path si no lo tenía:
alter function public.membership_batch_status(<ARGS>) set search_path = '';
```

Si quien la llama es tu backend, no concedas nada a `anon`/`authenticated`: invócala desde el servidor con
la `service_role` key, que ignora estos grants.
