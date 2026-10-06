#!/usr/bin/env bash
# Ayudante para instalar y lanzar Shannon contra un target de STAGING.
# Uso:  ./run-shannon.sh <STAGING_URL> <RUTA_AL_REPO>
# Ejemplo: ./run-shannon.sh http://localhost:3000 ~/code/mindupgrade-web
#
# NO lo apuntes a https://mindupgrade.app (producción). Shannon ejecuta exploits reales.
set -euo pipefail

URL="${1:-}"
REPO="${2:-}"

if [[ -z "$URL" || -z "$REPO" ]]; then
  echo "Uso: $0 <STAGING_URL> <RUTA_AL_REPO>" >&2
  exit 2
fi

if [[ "$URL" == *"mindupgrade.app"* ]]; then
  echo "ABORTADO: '$URL' parece producción. Usa un entorno de staging desechable." >&2
  exit 1
fi

if [[ "$(id -u)" == "0" ]]; then
  echo "ABORTADO: Shannon no debe correr como root. Usa un usuario con Docker sin sudo." >&2
  exit 1
fi

if [[ ! -d shannon ]]; then
  git clone https://github.com/KeygraphHQ/shannon.git
fi
cd shannon

if [[ ! -f .env ]]; then
  echo "Falta shannon/.env. Copia ../.env.example a .env y pon tu SHANNON_AI_API_KEY." >&2
  exit 1
fi

pnpm install
pnpm build

exec ./shannon start -u "$URL" -r "$REPO" --follow -o ../reports
