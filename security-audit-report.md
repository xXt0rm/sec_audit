# Auditoría de seguridad — mindupgrade.app

**Fecha:** 2026-10-06
**Objetivo:** `https://mindupgrade.app` y su código fuente `xXt0rm/mindupgrade-web`
**Commit auditado:** `4e2b8ca77c3e0b2896ac15914d4bad72ee95224a` (rama `main` clonada)
**Autor:** auditoría asistida por Claude Code, sobre propiedad del propio usuario (prueba autorizada)

---

## 1. Resumen ejecutivo

mindupgrade.app es una aplicación **Next.js 16 (App Router) + React 19** con **Supabase** para datos,
desplegada mediante **OpenNext detrás de Cloudflare**. Está en **fase temprana**: el checkout, el envío
de email (Resend), Stripe y PayPal son *stubs* no cableados, y la compra real se delega a **Gumroad**.

**Veredicto:** no se encontró ninguna vulnerabilidad crítica *explotable en el código actual* (no hay
inyección SQL, ni `eval`, ni `dangerouslySetInnerHTML`, ni secretos en el repositorio). La base es
razonablemente sólida. Los hallazgos son sobre todo de **endurecimiento** y de **verificación de backend**
que conviene resolver **antes de activar la parte comercial y el área de cuenta de usuario**.

Dos cosas merecen acción prioritaria:

1. **Dependencias con avisos conocidos**, incluido el propio **Next.js** (crítico según `npm audit`).
2. **La seguridad real de los datos depende de las políticas RLS de Supabase**, que **no se pueden
   verificar desde este repositorio** y deben comprobarse en el proyecto Supabase.

### Tabla de hallazgos

| ID | Hallazgo | Severidad | Estado |
|----|----------|-----------|--------|
| A | Faltan cabeceras HTTP de seguridad (CSP, HSTS, X-Frame-Options, etc.) | Media | Confirmado (en vivo + código) |
| B | Dependencias vulnerables, Next.js incluido | Alta | Confirmado (`npm audit`) |
| C | Clave service-role (salta RLS) usada en páginas públicas | Media | Confirmado (código) |
| D | La protección de datos depende de RLS de Supabase, sin verificar | Alta (verificar) | No verificable desde el repo |
| E | Ruta `/admin` y área de cuenta sin protección ni middleware | Baja (hoy) | Confirmado (código) |
| F | Sin rate-limiting / anti-abuso en endpoints de escritura públicos | Baja→Media | Confirmado (código) |
| G | PII (nombre/email) escrita a logs | Baja | Confirmado (código) |
| H | Sin `/.well-known/security.txt` | Informativa | Confirmado (en vivo) |
| I | El despliegue en vivo no coincide con el repo (robots.txt) | Informativa | Confirmado (en vivo) |

---

## 2. Alcance y método

**Incluido:**

- **Revisión estática** manual del código fuente (clientes Supabase, rutas API, server actions,
  formularios, `next.config.ts`, integración YouTube, utilidades).
- **Búsqueda de patrones peligrosos** en todo `app/`, `lib/`, `components/`, `scripts/`
  (`dangerouslySetInnerHTML`, `eval`, `innerHTML`, `child_process`, secretos embebidos, uso de
  service-role, variables de entorno).
- **Auditoría de dependencias** (`npm audit`) sobre el lockfile.
- **Comprobación pasiva externa** de mindupgrade.app: cabeceras de respuesta, TLS, `robots.txt`,
  `/.well-known/security.txt`, `/api/health`. Solo peticiones GET normales (equivalente a visitar la
  web); sin fuzzing, sin fuerza bruta, sin ataques activos.

**No incluido (y por qué):**

- **Pentest activo (ejecución real de exploits).** Es el trabajo que hace la herramienta **Shannon** que
  instalaste. No se ejecutó: requiere una **clave de API de un proveedor LLM** (que no tengo) y, sobre
  todo, **no debe lanzarse contra producción** (ver sección 6). Queda preparado para que lo lances tú
  contra un entorno de staging.
- **Verificación de políticas RLS de Supabase** (hallazgo D): no son visibles desde el frontend.
- **3 archivos de vista** (`app/checkout/gracias/page.tsx`, `app/(marketing)/mapa/[theme]/page.tsx`,
  `app/(marketing)/contacto/contact-form.tsx`) **no se revisaron línea a línea** por una restricción del
  entorno de auditoría. Sí quedaron cubiertos por la búsqueda global de *sinks* peligrosos, que no
  encontró ninguno en ellos.

**Advertencia importante (hallazgo I):** la `robots.txt` servida en vivo **no coincide** con la del
repositorio. Por tanto el commit desplegado puede ser distinto del `main` que audité. **Los hallazgos
de código son contra el repositorio**; conviene re-confirmarlos contra el commit realmente desplegado.

---

## 3. Hallazgos detallados

### A — Faltan cabeceras HTTP de seguridad · Media

**Evidencia:** la respuesta en vivo de `https://mindupgrade.app/` no incluye **ninguna** de las cabeceras
de seguridad habituales, y `next.config.ts` no define un bloque `headers()`.

Ausentes: `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP),
`X-Frame-Options` / `frame-ancestors`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
`Permissions-Policy`.

**Impacto:** sin `X-Frame-Options`/`frame-ancestors` la web es enmarcable (clickjacking). Sin HSTS no se
fuerza HTTPS en visitas futuras a nivel de navegador. Sin CSP no hay contención si algún día se introduce
una inyección de HTML/JS (defensa en profundidad), y se cargan scripts de terceros (Gumroad, Vercel
Analytics) sin restricción de origen.

**Remediación:** añade un bloque `headers()` en `next.config.ts`. Punto de partida (ajusta la CSP a los
orígenes reales: Gumroad, Vercel Analytics, Supabase, `i.ytimg.com`):

```ts
// next.config.ts
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  // CSP: empieza en Report-Only, revisa violaciones y luego hazla efectiva.
  {
    key: "Content-Security-Policy-Report-Only",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://gumroad.com https://*.gumroad.com https://va.vercel-scripts.com",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https://i.ytimg.com https://*.supabase.co https://placehold.co",
      "frame-src https://gumroad.com https://*.gumroad.com",
      "connect-src 'self' https://*.supabase.co",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self' https://gumroad.com",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  // ...resto de la config
};
```

Nota: estas cabeceras también pueden fijarse en Cloudflare (Transform Rules), pero tenerlas en la app las
versiona junto al código.

---

### B — Dependencias con vulnerabilidades conocidas (Next.js incluido) · Alta

**Evidencia (`npm audit` sobre el lockfile):**

| Conjunto | critical | high | moderate | low | total |
|----------|----------|------|----------|-----|-------|
| Todas las dependencias | 2 | 19 | 6 | 2 | **29** |
| Solo producción (`--omit=dev`) | 1 | 5 | 1 | 0 | **7** |

- La única dependencia **directa de runtime** marcada es **`next` (crítica)**. Los avisos sobre `next`
  cubren DoS, bypass de middleware/proxy, XSS en App Router con nonces de CSP, SSRF y RCE en la API de
  optimización de imágenes / `next/og`. La app usa `next/image` y `opengraph-image.tsx`, así que esa
  superficie es relevante.
- El resto de producción es transitivo del pipeline de imágenes y despliegue (`sharp`, `nanoid`,
  `postcss`, y utilidades de OpenNext/Cloudflare como `hono`, `ws`, `proxy-addr`, `qs`).
- Los **22 restantes** (de los 29) están en **herramientas de dev/build** (`eslint`, `shadcn`,
  `ts-morph`, `fast-glob`, `braces`, `micromatch`, `@babel/core`): ReDoS/DoS en tiempo de build, **bajo
  riesgo en producción**.

**Matiz honesto:** los títulos de los avisos son más recientes que mi conocimiento, así que no puedo
confirmar la explotabilidad exacta en el uso concreto de esta app. La prioridad es clara igualmente.

**Remediación:**

```bash
# en xXt0rm/mindupgrade-web
npm audit --omit=dev            # ver lo que realmente se despliega
npm audit fix                   # arreglos no disruptivos
# subir Next.js al último parche de la 16.x y re-auditar:
npm install next@latest eslint-config-next@latest
npm audit --omit=dev
```

Verifica el build (`npm run build`) tras subir Next.js. Considera activar **Dependabot/Renovate** para no
volver a acumular retraso.

---

### C — Clave service-role (salta RLS) usada en páginas públicas · Media

**Evidencia:**
- `app/(marketing)/recursos/[slug]/page.tsx` usa `createAdminClient()` en `generateStaticParams()` y
  `generateMetadata()`.
- `app/sitemap.ts` usa `createAdminClient()` para listar productos.
- `lib/supabase/admin.ts` crea el cliente con `SUPABASE_SERVICE_ROLE_KEY`.

El cliente service-role **salta por completo las políticas RLS** de Supabase. Hoy **no hay fuga**: todas
las consultas filtran `.eq("published", true)`. Pero:

- Es un uso **innecesario**: el cliente anónimo ya lee productos publicados en el cuerpo de la misma
  página y en `recursos/page.tsx`, luego RLS ya permite ese acceso.
- Elimina RLS como **red de seguridad**: si en el futuro alguien edita una de esas consultas y olvida el
  filtro `published`, expondría filas no publicadas sin que RLS lo impida.

**Remediación:** usa el cliente **anónimo** (`@/lib/supabase/server` o `@/lib/supabase/client`) en páginas
públicas y deja RLS como backstop. Reserva `createAdminClient()` para operaciones de administración
**autenticadas y verificadas por rol** en el servidor. El `try/catch` de `sitemap.ts` ya tolera la
ausencia de la clave; con el cliente anónimo deja de depender del service-role en build.

---

### D — La protección de datos depende de RLS de Supabase (sin verificar) · Alta (verificar)

**Contexto:** la URL del proyecto Supabase (`aorhazdvenarrbdympxo.supabase.co`) y la **anon key** son
públicas por diseño (van en el bundle con prefijo `NEXT_PUBLIC_`). Esto es correcto **solo si** cada tabla
tiene **Row Level Security activado y con políticas correctas**. Eso **no es visible desde el frontend**,
así que no forma parte de lo que pude auditar, pero es **lo más importante** en una app Supabase.

**Acción recomendada (en el panel de Supabase o por SQL):**

- Confirma `ROW LEVEL SECURITY` **habilitado en todas las tablas** (no solo `products`; también cualquier
  tabla futura de pedidos, usuarios, waitlist…).
- `products`: el rol `anon` solo debe poder **leer** filas con `published = true`, y **nunca** escribir.
- Ninguna tabla con datos personales o de pedidos debe ser legible/escribible por `anon`.
- Revisa que la **service-role key** solo viva en variables de entorno del servidor (lo está: ver
  `lib/supabase/admin.ts` con `import "server-only"`), nunca en el cliente.

Comprobación rápida de RLS:

```sql
select relname, relrowsecurity
from pg_class
where relnamespace = 'public'::regnamespace and relkind = 'r';
-- relrowsecurity debe ser true en todas.
```

---

### E — `/admin` y área de cuenta sin protección; no hay middleware · Baja (hoy)

**Evidencia:** `app/admin/page.tsx` es un placeholder público ("Panel admin (placeholder)"). No existe
`middleware.ts` en el repo. `app/robots.ts` desaconseja `/admin`, `/mi-cuenta`, `/api`, `/callback`, pero
`robots.txt` es **solo orientativo**, no un control de acceso. `/mi-cuenta` y `/callback` aún no existen
(serán el área de cuenta/login).

**Impacto:** hoy nulo (la página no expone nada). El riesgo es **a futuro**: en cuanto `/admin` tenga
funciones reales, serían accesibles sin autenticación si no se añade un guard antes.

**Remediación:** antes de construir el admin, añade verificación de sesión Supabase + rol, y un
`middleware.ts` que proteja `/admin`, `/mi-cuenta` y las rutas de API privadas, además de refrescar la
sesión (nota: `lib/supabase/server.ts` menciona "el proxy refresca la sesión", pero ese middleware no
existe todavía).

---

### F — Sin rate-limiting / anti-abuso en endpoints de escritura públicos · Baja → Media (en lanzamiento)

**Evidencia:** `POST /api/checkout`, la server action `sendContactAction` y el formulario de waitlist no
tienen límite de tasa ni protección anti-bot.

**Impacto hoy:** limitado (checkout es un stub que simula `orderId`; contacto y waitlist solo hacen
`console.log`). **Al lanzar:** cuando se cablee **Resend**, contacto y waitlist pasan a ser vectores de
**spam y de inyección de cabeceras de email**; checkout real necesita evitar abuso.

**Remediación:** añade rate-limiting (p. ej. Upstash Ratelimit o Cloudflare Turnstile/WAF) a esos
endpoints. Al integrar Resend: remitente **fijo** del lado servidor, **nunca** cabeceras controladas por
el usuario, y validación/escape del contenido. Nota positiva: `/api/checkout` ya valida email, ya fuerza
el **mínimo de precio desde la base de datos** (no confía en el importe del cliente) y usa consultas
parametrizadas de Supabase (sin SQLi).

---

### G — PII escrita a logs · Baja

**Evidencia:** `app/(marketing)/contacto/actions.ts` hace `console.log("[contacto]", { name, email, message })`
y `waitlist-form.tsx` hace `console.log("[waitlist] meditaciones", email)`. En serverless esto va a logs
persistentes.

**Remediación:** elimina o redacta estos logs antes de producción; evita registrar email/mensaje en claro.

---

### H — Sin `security.txt` · Informativa

`https://mindupgrade.app/.well-known/security.txt` devuelve 404. Añade un `security.txt` (RFC 9116) con un
contacto de divulgación responsable. En Next: `app/.well-known/security.txt/route.ts` o estático en
`public/.well-known/`.

---

### I — El despliegue en vivo no coincide con el repo · Informativa (con implicación SEO)

**Evidencia:** `robots.txt` en vivo devuelve `User-Agent: *` / `Disallow: /` (bloquea **toda** la web),
mientras que `app/robots.ts` en el repo genera `allow: "/"` con exclusiones concretas.

**Implicaciones:**
1. El **commit desplegado difiere** del `main` auditado → re-confirma los hallazgos contra el commit real.
2. Si ese `Disallow: /` es **involuntario**, está **desindexando toda la web** de buscadores (problema de
   SEO serio para un proyecto que depende de tráfico). Si es intencional (soft-launch), ignóralo.

---

## 4. Lo que está bien (controles correctos)

- **Sin secretos en el repositorio.** `.gitignore` excluye `.env*`, `*.pem` y `.mcp.json`; no hay ningún
  `.env` versionado ni claves embebidas. La service-role key solo se lee en un módulo `server-only`.
- **Checkout con patrón correcto:** el **precio mínimo se valida en el servidor desde la base de datos**,
  no se confía en el importe que manda el cliente; el email se valida; el `slug` va como filtro
  parametrizado (sin inyección SQL).
- **`images.remotePatterns` es una allowlist estricta** (`placehold.co`, el proyecto Supabase,
  `i.ytimg.com`), lo que limita el abuso/SSRF del optimizador de imágenes de Next.
- **Sin sinks peligrosos** en el código de la app: no hay `dangerouslySetInnerHTML`, `eval`,
  `new Function`, `innerHTML` ni ejecución de shell. React escapa por defecto.
- **Pagos delegados a Gumroad**, lo que saca de alcance el manejo de tarjetas (PCI). Stripe/PayPal/Resend
  aún no cableados ⇒ superficie actual menor.
- **TLS válido**, HTTP/2 y HTTP/3, detrás de Cloudflare.

---

## 5. Verificaciones de backend pendientes (hazlas tú)

1. **RLS en Supabase** (hallazgo D) — lo más importante.
2. **Rotación de claves** si la service-role key ha estado alguna vez en un `.env.local` compartido o en
   logs de build.
3. **Re-confirmar hallazgos contra el commit realmente desplegado** (hallazgo I).

---

## 6. Pentest activo con Shannon — preparado para que lo lances tú

Shannon (de KeygraphHQ) quedó **instalado y compilado** en esta sesión. No ejecuté un escaneo por dos
motivos, ambos tuyos de resolver:

1. **Clave de API de un proveedor LLM (BYOK).** Shannon necesita tu propia clave (Anthropic, OpenAI, xAI o
   Bedrock). No la tengo y no debo inventarla. Antes del primer escaneo, completa la **verificación de
   uso ciberseguridad** de tu proveedor (Anthropic/OpenAI aplican salvaguardas que interrumpen escaneos si
   no la tienes).
2. **No se debe lanzar contra producción.** La propia documentación de Shannon avisa: *ejecuta exploits
   reales* (crea usuarios, muta estado, dispara peticiones salientes) y **"no lo ejecutes contra sistemas
   de producción"**. mindupgrade.app es tu web en producción detrás de Cloudflare: un escaneo activo
   podría crear datos basura, disparar el WAF o bloquear tu IP.

**Recomendación:** despliega `mindupgrade-web` en un **staging desechable** (preview de Vercel, o local con
`npm run build && npm start`) apuntando a un **proyecto Supabase de usar y tirar**, y lanza Shannon contra
ESA URL, con el repo como fuente.

Instrucciones completas y reproducibles en **`shannon/SETUP.md`** de este repositorio. Resumen del comando
(ejecútalo como usuario **no-root** con Docker, Shannon bloquea root):

```bash
./shannon start -u https://staging.mindupgrade.app -r /ruta/a/mindupgrade-web
```

---

## 7. Apéndice — superficie inventariada

**Stack:** Next.js 16.2.4 (App Router), React 19.2.4, Supabase (`@supabase/ssr`, `supabase-js`),
Vercel Analytics, Tailwind 4, OpenNext + Cloudflare.

**Rutas dinámicas / endpoints:**
- `POST /api/checkout` — valida slug/email/importe; mínimo desde DB; hoy simula `orderId` (stub).
- `GET /api/health` — `{status:"ok"}`, sin fuga de info.
- `app/(marketing)/recursos/[slug]` — detalle de producto (usa service-role en metadata; ver C).
- `app/(marketing)/mapa/[theme]` — página de tema (no revisada línea a línea; sin sinks según grep).
- Server action `sendContactAction` — stub (log + delay).
- Waitlist meditaciones — stub en cliente (log + toast).

**Integraciones:** Gumroad (compra), YouTube Data API v3 (sync de metadatos, clave server-side),
Supabase. Stripe/PayPal/Resend = stubs (`null`).
