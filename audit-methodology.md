# Auditoría completa sin ser invasiva — metodología

**La pregunta:** un Supabase de prueba no replica tus políticas RLS ni tu config real, así que probar
solo contra staging deja fuera lo que más importa. ¿Cómo hacemos una auditoría **completa** sin que sea
**invasiva** contra producción?

**La respuesta:** se separa la auditoría en capas. **Solo una capa es invasiva** (la ejecución real de
exploits). Esa capa corre sobre una **copia fiel** de producción, no sobre producción. Todas las demás
capas se auditan **contra producción en modo solo lectura**, lo que no es invasivo.

---

## Mapa de cobertura

| Capa | Qué cubre | ¿Invasiva? | Dónde se ejecuta | Estado |
|------|-----------|------------|------------------|--------|
| 1. SAST (código) | Lógica, inyección, authz, secretos | No | Repositorio | **Hecho** (ver `security-audit-report.md`) |
| 2. SCA (dependencias) | CVEs de librerías | No | Repositorio | **Hecho** (`npm audit`) |
| 3. Config Supabase | **RLS real, privilegios, funciones** | No, solo lectura | **Producción** | **Listo para ti** (`supabase-security-audit.sql`) |
| 4. Config plataforma | Cabeceras, TLS, Cloudflare, Auth URLs | No, solo lectura | Producción | Parcial (externo hecho; panel pendiente) |
| 5. DAST pasivo / autenticado | App en marcha, sin mutar estado | Mínima, controlada | Producción | Guion abajo |
| 6. Pentest activo (Shannon) | Prueba de explotación real | **Sí** | **Staging espejo** | Requiere tu acción |

Las capas 1 a 5 dan una auditoría casi completa **sin tocar producción de forma invasiva**. La capa 6 es
la única invasiva, y se neutraliza el riesgo con una copia fiel.

---

## Capa 3 — Config de Supabase (lo que te preocupaba), en producción y sin riesgo

Lo que diferencia staging de producción son las **políticas RLS** y la **configuración**. No necesitas
*atacar* producción para auditarlas: puedes **leerlas** directamente, que es inofensivo.

1. Abre el **SQL Editor** de tu proyecto de producción en Supabase.
2. Pega y ejecuta **`supabase-security-audit.sql`** de este repo. Son solo `SELECT` contra catálogos del
   sistema. No escribe nada.
3. Pásame los resultados y te los interpreto, o revisa tú las notas de cada bloque.

Esto audita tu postura de seguridad **real** (la de producción) sin invasión. Es la pieza que un Supabase
de prueba no podía darte.

---

## Capa 6 — Pentest activo sobre una copia FIEL (no un Supabase de prueba cualquiera)

El problema que señalas desaparece si staging **no** es un Supabase vacío, sino un **espejo** de
producción en todo lo relevante para seguridad. Lo único que debe cambiar son los **datos** (sintéticos,
no reales).

**Receta del espejo:**

1. **Clona el esquema Y las políticas** de producción a un proyecto desechable, con el CLI de Supabase:
   ```bash
   # Vuelca esquema + RLS + funciones + grants de producción (sin datos):
   supabase db dump --db-url "$PROD_DB_URL" --schema public -f schema.sql
   # Aplica ese mismo esquema al proyecto de staging:
   psql "$STAGING_DB_URL" -f schema.sql
   ```
   Así staging tiene **tus mismas políticas RLS y funciones**. La lógica de seguridad es idéntica.
2. **Carga datos sintéticos** (usuarios y pedidos de mentira), nunca datos reales de clientes.
3. **Misma configuración:** mismas variables de entorno, Gumroad/Resend/Stripe en **modo test**, mismos
   Redirect URLs de Auth adaptados al dominio de staging.
4. **Despliega `mindupgrade-web`** apuntando a ese staging (preview de Vercel o local).
5. **Lanza Shannon** contra esa URL (ver `shannon/SETUP.md`).

Como RLS y la lógica son idénticas a producción, **los hallazgos de Shannon en el espejo aplican a
producción**. Pruebas el comportamiento real sin crear basura ni arriesgar tu sitio en vivo.

---

## Capa 5 — Qué sí se puede comprobar en producción sin mutar nada

Pruebas de app en marcha que **no escriben** estado:

- Cabeceras de seguridad, TLS, flags de cookies, CORS.
- Flujo de login **con una cuenta de prueba tuya** (no crear usuarios basura en bucle).
- Observar el comportamiento de rate-limit sin forzarlo (sin fuerza bruta).
- Comprobar que endpoints privados (`/admin`, futuro `/mi-cuenta`) exigen sesión.

Se evita todo lo que cree, borre o modifique datos, pague, o dispare emails.

---

## El límite honesto

Lo único que **no** se puede obtener de forma no invasiva es la *prueba de explotación* contra los
**datos reales de producción**. Eso es inherentemente invasivo y no se debe hacer contra un sitio en vivo.
El espejo fiel (capa 6) cubre casi todo ese hueco, porque la seguridad depende de la **config y la
lógica**, no de los datos, y esas sí las replicamos al 100%. La parte residual (p. ej. datos concretos que
disparan un caso límite) se cubre con la auditoría de config en producción solo lectura (capa 3).

---

## Qué necesito de ti para avanzar

1. **Capa 3 ahora mismo:** ejecuta `supabase-security-audit.sql` en producción y mándame la salida. Cero
   riesgo, máximo valor, y ataca justo tu preocupación.
2. **Capa 4 (panel):** acceso o capturas de API settings, Auth URL config y Storage de Supabase, más las
   reglas de Cloudflare, para auditar config sin tocar nada.
3. **Capa 6 cuando quieras:** monta el espejo con la receta de arriba y una credencial LLM; te dejo el
   comando exacto de Shannon.
