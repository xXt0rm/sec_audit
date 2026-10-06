# Auditoría de seguridad — mindupgrade.app

Este repositorio contiene la auditoría de seguridad de **mindupgrade.app** (web propiedad del usuario,
prueba autorizada) y el *handoff* para ejecutar el pentester **Shannon** de KeygraphHQ.

## Contenido

- **`security-audit-report.md`** — informe completo: resumen ejecutivo, método, 9 hallazgos con
  evidencia y remediación, controles que están bien, y verificaciones de backend pendientes.
- **`audit-methodology.md`** — cómo hacer una auditoría **completa sin ser invasiva** contra producción:
  capas, qué se audita en producción en solo lectura, y cómo montar un **staging espejo fiel** para la
  única capa invasiva (Shannon).
- **`supabase-security-audit.sql`** / **`supabase-security-audit-oneshot.sql`** — scripts **solo lectura**
  para auditar la config real de tu Supabase de producción (RLS, privilegios de anon, funciones SECURITY
  DEFINER). No modifican nada.
- **`supabase-findings.md`** — **resultados** de la auditoría de Supabase (Security Advisor). Veredicto:
  0 errores, datos sensibles bien aislados en un esquema `private` con RLS. Único punto a arreglar: una
  función SECURITY DEFINER (`public.membership_batch_status()`) ejecutable por anónimos. Incluye consultas
  de inspección y la remediación.
- **`shannon/SETUP.md`** — cómo instalar y lanzar Shannon tú mismo, contra staging (no producción).
- **`shannon/.env.example`** — plantilla de credenciales BYOK para Shannon.
- **`shannon/run-shannon.sh`** — script ayudante que instala Shannon y lanza un escaneo contra una URL de
  staging (rechaza producción y rechaza root).

## Resumen en una línea

App Next.js 16 + Supabase en fase temprana, con base sólida (sin secretos filtrados, sin inyección, sin
`eval`/`dangerouslySetInnerHTML`). Acciones prioritarias: **subir Next.js y resolver avisos de `npm
audit`**, **verificar las políticas RLS de Supabase**, y **añadir cabeceras HTTP de seguridad**. El
pentest activo con Shannon queda preparado para que lo lances contra un **staging** (requiere tu clave de
API LLM; no debe correrse contra producción).

## Qué se hizo en esta sesión

1. Se clonó y **compiló Shannon** desde fuente (quedó funcional; no se ejecutó un escaneo — ver el informe,
   sección 6).
2. Se hizo una **revisión estática** del código de `xXt0rm/mindupgrade-web`.
3. Se hizo una **comprobación pasiva externa** de mindupgrade.app (cabeceras, TLS, robots, security.txt).
4. Se ejecutó **`npm audit`** sobre las dependencias.

Lee **`security-audit-report.md`** para el detalle completo.
