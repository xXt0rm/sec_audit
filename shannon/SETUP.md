# Shannon — instalación y ejecución (handoff)

Shannon es el pentester autónomo de IA de KeygraphHQ (`https://github.com/KeygraphHQ/shannon`).
En esta sesión quedó **clonado y compilado** (commit `45062a8`). Como el contenedor de esta sesión es
efímero, abajo tienes los pasos **reproducibles** para instalarlo y lanzarlo tú.

## Requisitos

- **Docker** (demonio en marcha) + Docker Compose v2.
- **Node.js 18+** y **pnpm**.
- **Usuario no-root.** Shannon **se niega a ejecutarse como root** por seguridad. Usa una cuenta normal
  con Docker sin sudo: `https://docs.docker.com/engine/install/linux-postinstall`.
- **Clave de API de un proveedor LLM (BYOK):** Anthropic, OpenAI, xAI o AWS Bedrock.
- **Verificación de ciberseguridad del proveedor** completada antes del primer escaneo
  (`https://github.com/KeygraphHQ/shannon/discussions/483`). Sin ella, Anthropic/OpenAI pueden
  interrumpir el escaneo a mitad.

## Instalación (desde fuente)

```bash
git clone https://github.com/KeygraphHQ/shannon.git
cd shannon
cp .env.example .env     # edita .env y pon tu clave (ver shannon/.env.example de este repo)
pnpm install
pnpm build
```

O, más simple, el instalador interactivo publicado:

```bash
npx @keygraph/shannon@latest setup
```

## ⚠️ Antes de lanzar: NO apuntes a producción

La documentación de Shannon es explícita: ejecuta **exploits reales** (crea usuarios, muta estado, lanza
peticiones salientes) y **no debe usarse contra sistemas de producción**. `mindupgrade.app` es tu web en
producción detrás de Cloudflare.

**Haz esto en su lugar:**

1. Despliega `mindupgrade-web` en un **entorno de staging desechable**:
   - Preview de Vercel, **o**
   - Local: `npm run build && npm start` (queda en `http://localhost:3000`).
2. Apúntalo a un **proyecto Supabase de usar y tirar** (no el de producción), con datos de prueba.
3. Lanza Shannon contra ESA URL.

## Ejecución

```bash
# Fuente compilada:
./shannon start -u https://staging.mindupgrade.app -r /ruta/a/mindupgrade-web

# o con el paquete npx:
npx @keygraph/shannon start -u http://localhost:3000 -r /ruta/a/mindupgrade-web
```

Opciones útiles:

```bash
./shannon start -u <url> -r <repo> --follow        # sigue el log hasta terminar
./shannon start -u <url> -r <repo> -o ./reports    # copia los informes a ./reports
./shannon status   # estado del escaneo
./shannon logs     # log combinado en vivo
./shannon stop     # detener
```

## Resultados

Informe final en PDF + Markdown, más JSON y SARIF 2.1.0, en `./workspaces/<host>_<id>/`
(fuente) o `~/.shannon/workspaces/` (npx). Shannon solo reporta vulnerabilidades con **prueba de
concepto reproducible** ("no exploit, no report"); aun así, **revisa los hallazgos a mano**: los informes
generados por LLM pueden contener detalles incorrectos.

## Notas de este entorno

- En el contenedor de la sesión, Docker estaba instalado pero el demonio no arrancado; se arrancó como
  root para la instalación. Para **ejecutar** Shannon se necesita un usuario no-root con acceso a Docker,
  algo que no se pudo configurar aquí sin debilitar permisos del socket de Docker (acción bloqueada por la
  política de seguridad del entorno, correctamente). En tu máquina/CI con Docker sin sudo no hay problema.
- Alternativa sin gestionar infra tú: la **GitHub Action oficial** `KeygraphHQ/shannon-action@v1` corre
  Shannon en CI contra un target de staging y sube el SARIF a GitHub code scanning.
