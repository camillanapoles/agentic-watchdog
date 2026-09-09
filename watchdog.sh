#!/usr/bin/env bash
# ============================================================================
# agentic-watchdog — Sentinela de visibilidade + guarda de inatividade
# ----------------------------------------------------------------------------
# Contrato (estado final desejado):
#   1. TARGET_REPO é PRIVADO por padrão (plano: Actions só rodam em público).
#   2. MODE=detect  — detecta automaticamente transições de visibilidade
#                     (privado➞público e público➞privado), persiste estado no
#                     branch `state` (trilha de auditoria) e, ao capturar uma
#                     abertura, dispara o workflow de guarda.
#   3. MODE=guard   — com o alvo público: monitora inatividade (sem push) e,
#                     se ≥ INACTIVITY_MINUTES (default 30), converte
#                     público➞privado, VERIFICA a conversão via API e registra.
#                     Fail-safes: adiamento se houver runs de CI ativos;
#                     3 tentativas + verificação pós-ação; issue crítica se a
#                     conversão não confirmar; nunca age sob dados incertos
#                     (erros de API ⇒ aborta sem tocar no repo alvo).
#
# Operação / rotação de segredo:
#   WATCHDOG_PAT hoje é o token OAuth do `gh` (escopos repo+workflow).
#   Recomendado: trocar por fine-grained PAT com Administration: RW +
#   Metadata: R apenas no TARGET_REPO, e Actions: RW + Issues: RW no watchdog.
#
# Variáveis de ambiente:
#   WATCHDOG_PAT         (obrigatório) token com poder de admin no alvo
#   TARGET_REPO          default camillanapoles/agentic
#   WATCHDOG_REPO        repo do watchdog (p/ dispatch e issues)
#   INACTIVITY_MINUTES   default 60
#   DRY_RUN              true|false (default false) — não converte, só reporta
#   GH_TOKEN             token do runner p/ push de estado e dispatch (sentinel)
# ============================================================================
set -euo pipefail

MODE="${1:-detect}"
TARGET_REPO="${TARGET_REPO:-camillanapoles/agentic}"
WATCHDOG_REPO="${WATCHDOG_REPO:-camillanapoles/agentic-watchdog}"
INACTIVITY_MINUTES="${INACTIVITY_MINUTES:-30}"
DRY_RUN="${DRY_RUN:-false}"
STATE_BRANCH="${STATE_BRANCH:-state}"
STATE_FILE="state/state.json"
API="https://api.github.com"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "FATAL: $*"; exit 1; }

# ---- GitHub API com retry e fail-closed ------------------------------------
api() {
  local method="$1" path="$2" data="${3:-}"
  local args=(--silent --show-error --fail --retry 3 --retry-delay 5
              --request "$method"
              -H "Authorization: Bearer ${WATCHDOG_PAT:?sem WATCHDOG_PAT}"
              -H "Accept: application/vnd.github+json"
              -H "X-GitHub-Api-Version: 2022-11-28"
              "$API$path")
  [[ -n "$data" ]] && args+=(-d "$data")
  curl "${args[@]}" || die "API falhou: $method $path — abortando SEM agir no alvo"
}

# ---- Estado persistido no branch `state` (auditoria) -----------------------
sync_state_branch() {
  if git ls-remote --exit-code --heads origin "$STATE_BRANCH" >/dev/null 2>&1; then
    git fetch -q origin "$STATE_BRANCH"
    git checkout -q -B "$STATE_BRANCH" FETCH_HEAD
  else
    git checkout -q --orphan "$STATE_BRANCH"
    git rm -rqf --cached . >/dev/null 2>&1 || true
    git clean -qfdx -e state >/dev/null 2>&1 || true
  fi
  mkdir -p state
}

load_state() {
  [[ -f "$STATE_FILE" ]] && cat "$STATE_FILE" || echo '{}'
}

save_state() { # save_state <json>
  printf '%s\n' "$1" > "$STATE_FILE.tmp"
  if [[ -f "$STATE_FILE" ]] && jq -e . "$STATE_FILE" >/dev/null 2>&1 \
     && diff -q <(jq -S . "$STATE_FILE") <(jq -S . "$STATE_FILE.tmp") >/dev/null; then
    rm -f "$STATE_FILE.tmp"; log "estado inalterado — sem commit"; return
  fi
  mv "$STATE_FILE.tmp" "$STATE_FILE"
  git add "$STATE_FILE"
  git commit -qm "state(${MODE}): $(printf '%s' "$1" | jq -c '{visibility,public_since,last_push}')"
  git push -q origin "$STATE_BRANCH"
  log "estado persistido no branch ${STATE_BRANCH}"
}

iso_to_epoch() { date -u -d "${1:?}" +%s; }
now_epoch()    { date -u +%s; }

# ---- Leitura do alvo --------------------------------------------------------
fetch_target() {
  TARGET_JSON="$(api GET "/repos/${TARGET_REPO}")" \
    || die "não foi possível ler ${TARGET_REPO}"
  TARGET_PRIVATE="$(jq -r '.private' <<<"$TARGET_JSON")"
  TARGET_PUSHED="$(jq -r '.pushed_at' <<<"$TARGET_JSON")"
  [[ "$TARGET_PRIVATE" == true ]] && TARGET_VIS=private || TARGET_VIS=public
}

open_issue() { # open_issue <titulo> <corpo>
  if [[ -n "${GH_TOKEN:-}" ]]; then
    GH_TOKEN="$GH_TOKEN" gh issue create -R "$WATCHDOG_REPO" \
      --title "$1" --body "$2" >/dev/null 2>&1 || true
  fi
}

# ============================================================================
# MODE=detect — sentinela de transições
# ============================================================================
do_detect() {
  fetch_target
  local state prev public_since
  state="$(load_state)"
  prev="$(jq -r '.visibility // empty' <<<"$state")"
  public_since="$(jq -r '.public_since // empty' <<<"$state")"
  log "alvo=${TARGET_REPO} vis=${TARGET_VIS} prev=${prev:-<none>} pushed_at=${TARGET_PUSHED}"

  if [[ "$TARGET_VIS" == public && "$prev" != public ]]; then
    log "TRANSIÇÃO CAPTURADA: privado ➞ público — armando guarda de inatividade (${INACTIVITY_MINUTES} min)"
    save_state "$(jq -n --arg v public --arg ps "$(date -u +%FT%TZ)" --arg lp "$TARGET_PUSHED" \
      '{visibility:$v, public_since:$ps, last_push:$lp}')"
    if [[ -n "${GH_TOKEN:-}" ]]; then
      GH_TOKEN="$GH_TOKEN" gh workflow run guard.yml -R "$WATCHDOG_REPO" \
        -f inactivity_minutes="$INACTIVITY_MINUTES" \
      && log "guard.yml disparado" || log "WARN: falha ao disparar guard.yml (cron o cobrirá)"
    fi
  elif [[ "$TARGET_VIS" == private && "$prev" == public ]]; then
    log "transição público ➞ privado registrada (manual ou guarda)"
    save_state "$(jq -n --arg v private --arg lp "$TARGET_PUSHED" \
      '{visibility:$v, public_since:null, last_push:$lp}')"
  else
    save_state "$(jq -n --arg v "$TARGET_VIS" \
        --argjson ps "$([[ $TARGET_VIS == public ]] && printf '"%s"' "${public_since:-$(date -u +%FT%TZ)}" || echo null)" \
        --arg lp "$TARGET_PUSHED" \
        '{visibility:$v, public_since:$ps, last_push:$lp}')"
  fi
}

# ============================================================================
# MODE=guard — inatividade ➞ reconversão verificada
# ============================================================================
active_runs_count() {
  # Runs ativas RECENTES = entregas reais em andamento. Runs queued/in_progress
  # há mais de ACTIVE_RUN_MAX_AGE_MIN (default 45) são zumbis (ex.: dependabot
  # dinâmico travado) e NÃO adiam a reconversão — apenas contam como alerta.
  local runs now
  runs="$(api GET "/repos/${TARGET_REPO}/actions/runs?per_page=100")"
  now="$(now_epoch)"
  jq --argjson now "$now" --argjson max_age $(( ${ACTIVE_RUN_MAX_AGE_MIN:-45} * 60 )) '
    [.workflow_runs[]
      | select(.status == "in_progress" or .status == "queued")
      | select(($now - (.created_at | sub("\\.[0-9]+Z$"; "Z") | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime)) < $max_age)]
    | length' <<<"$runs"
}

do_guard() {
  fetch_target
  sync_state_branch
  if [[ "$TARGET_VIS" == private ]]; then
    log "alvo já privado — nada a fazer (estado padrão ✔)"
    save_state "$(jq -n --arg v private --arg lp "$TARGET_PUSHED" '{visibility:$v, public_since:null, last_push:$lp}')"
    return 0
  fi

  local state public_since ref_epoch idle_min runs
  state="$(load_state)"
  public_since="$(jq -r '.public_since // empty' <<<"$state")"
  [[ -z "$public_since" ]] && public_since="$(date -u +%FT%TZ)"  # primeira observação

  # ESPERA ATIVA INLINE: o schedule do GitHub (free) sofre jitter alto (ticks
  # irregulares); este run NÃO depende de novo tick — aguarda até o limite de
  # inatividade (com folga) e converte no mesmo run.
  local deadline=$(( $(now_epoch) + (INACTIVITY_MINUTES + 10) * 60 ))
  while :; do
    fetch_target   # revalida: janela pode ter sido fechada manualmente
    if [[ "$TARGET_VIS" == private ]]; then
      log "alvo fechado manualmente durante a espera — registrado"
      save_state "$(jq -n --arg v private --arg lp "$TARGET_PUSHED" '{visibility:$v, public_since:null, last_push:$lp}')"
      return 0
    fi

    local pushed_epoch=0 ps_epoch
    [[ -n "$TARGET_PUSHED" && "$TARGET_PUSHED" != null ]] && pushed_epoch="$(iso_to_epoch "$TARGET_PUSHED")"
    ps_epoch="$(iso_to_epoch "$public_since")"
    ref_epoch=$(( pushed_epoch > ps_epoch ? pushed_epoch : ps_epoch ))
    idle_min=$(( ( $(now_epoch) - ref_epoch ) / 60 ))
    (( idle_min >= INACTIVITY_MINUTES )) && break
    if (( $(now_epoch) >= deadline )); then
      log "deadline de espera atingido — próxima guarda (cron/dispatch) converte, idle=${idle_min}min"
      save_state "$(jq -n --arg v public --arg ps "$public_since" --arg lp "$TARGET_PUSHED" \
        '{visibility:$v, public_since:$ps, last_push:$lp}')"
      return 0
    fi
    log "aguardando: inatividade ${idle_min}/${INACTIVITY_MINUTES} min (espera ativa neste run)"
    save_state "$(jq -n --arg v public --arg ps "$public_since" --arg lp "$TARGET_PUSHED" \
      '{visibility:$v, public_since:$ps, last_push:$lp}')" || true
    sleep 60
  done

  log "público desde ${public_since}; inatividade ${idle_min} min ≥ limite ${INACTIVITY_MINUTES}"

  # fail-safe: não interromper CI ativo (runs recentes; zumbis >45min não contam)
  local waited=0
  while :; do
    runs="$(active_runs_count)"
    (( runs == 0 )) && break
    if (( $(now_epoch) >= deadline )); then
      log "ADIADO definitivo: ${runs} run(s) ativa(s) e deadline esgotado — próximo tick converte"
      return 0
    fi
    log "ADIADO: ${runs} run(s) de CI ativa(s) — não interromper entregas (esperando)"
    sleep 60; waited=$((waited+1))
  done

  if [[ "$DRY_RUN" == true ]]; then
    log "DRY_RUN: converteria ${TARGET_REPO} para privado agora"; return 0
  fi

  log "inativo ≥ ${INACTIVITY_MINUTES} min — convertendo público ➞ privado"
  local attempt ok=false
  for attempt in 1 2 3; do
    api PATCH "/repos/${TARGET_REPO}" '{"private":true}' >/dev/null
    sleep 3
    fetch_target
    if [[ "$TARGET_VIS" == private ]]; then ok=true; break; fi
    log "tentativa ${attempt}: conversão não confirmada, repetindo"
  done
  if [[ "$ok" != true ]]; then
    open_issue "[watchdog] FALHA: ${TARGET_REPO} segue público" \
      "Guarda não confirmou a reconversão após 3 tentativas. Verificar manualmente."
    die "reconversão NÃO confirmada — issue crítica aberta"
  fi

  log "VERIFICADO via API: ${TARGET_REPO} privado ✔ (attempt ${attempt})"
  save_state "$(jq -n --arg v private --arg lp "$TARGET_PUSHED" '{visibility:$v, public_since:null, last_push:$lp}')"
  log "ciclo completo: público ➞ privado ➞ testado ➞ validado ✔"
}

# ----------------------------------------------------------------------------
git config user.name  "${GIT_AUTHOR_NAME:-watchdog-bot}"
git config user.email "${GIT_AUTHOR_EMAIL:-watchdog-bot@users.noreply.github.com}"

case "$MODE" in
  detect) sync_state_branch; do_detect ;;
  guard)  do_guard ;;
  *) die "uso: watchdog.sh [detect|guard]" ;;
esac
