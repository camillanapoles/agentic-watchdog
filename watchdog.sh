#!/usr/bin/env bash
# ============================================================================
# agentic-watchdog — Sentinela de visibilidade + guarda de inatividade
# ----------------------------------------------------------------------------
# Contrato (estado final desejado):
#   1. Todos os repos em TARGET_REPOS são PRIVADOS por padrão (plano: Actions
#      só rodam em público).
#   2. MODE=detect  — varre TODOS os alvos, detecta transições de visibilidade
#                     (privado➞público e público➞privado), persiste estado no
#                     branch `state` (trilha de auditoria; UM commit por ciclo,
#                     não um por repo) e, ao capturar uma abertura, dispara
#                     guard.yml com input target=<repo> (guarda DEDICADA por
#                     repositório).
#   3. MODE=guard   — alvo: GUARD_TARGET (um repo; caminho do dispatch da
#                     sentinela) ou, sem ele, TODOS em TARGET_REPOS (caminho
#                     do cron). Com o alvo público: monitora inatividade (sem
#                     push) e, se ≥ INACTIVITY_MINUTES (default 30), converte
#                     público➞privado, VERIFICA a conversão via API e registra.
#                     Fail-safes: adiamento se houver runs de CI ativos
#                     (recentes <45min; zumbis não contam); 3 tentativas +
#                     verificação pós-ação; issue crítica se a conversão não
#                     confirmar; nunca age sob dados incertos (erros de API ⇒
#                     aborta sem tocar no repo alvo).
#
# Multi-alvo:
#   TARGET_REPOS — lista separada por vírgula, espaço ou quebra de linha
#                  (ex.: "owner/a,owner/b"). Vazio ⇒ fallback retrocompatível
#                  para TARGET_REPO (single-alvo).
#   Estado (branch `state`, state/state.json): dict chaveado por repo —
#     {"owner/name": {visibility, public_since, last_push}, ...}
#   Migração: o formato legado (chaves top-level visibility/public_since/
#   last_push) é convertido no primeiro ciclo e atribuído ao TARGET_REPO
#   antigo, preservando a trilha existente.
#   Guarda por repo: o deadline de espera é do RUN (início+(N+10)min), logo a
#   guarda em paralelo só é possível com uma run POR repo (target=<repo>) —
#   groups de concurrency separados: sentinel | guard-<repo> | guard-all.
#
# Operação / rotação de segredo:
#   WATCHDOG_PAT hoje é o token OAuth do `gh` (escopos repo+workflow).
#   Recomendado: trocar por fine-grained PAT com Administration: RW +
#   Metadata: R nos repos alvo, e Actions: RW + Issues: RW no watchdog.
#
# Variáveis de ambiente:
#   WATCHDOG_PAT         (obrigatório) token com poder de admin nos alvos
#   TARGET_REPOS         lista de alvos (vírgula/espaço/quebra); vazio ⇒ TARGET_REPO
#   TARGET_REPO          alvo legado (fallback + dono da trilha de estado antiga)
#   GUARD_TARGET         (guard) um único repo; vazio ⇒ itera TARGET_REPOS
#   WATCHDOG_REPO        repo do watchdog (p/ dispatch e issues)
#   INACTIVITY_MINUTES   default 30
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
LEGACY_REPO="$TARGET_REPO"   # dono da trilha do formato antigo de state.json
GUARD_TARGET="${GUARD_TARGET:-}"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "FATAL: $*"; exit 1; }

# ---- Alvos (multi-alvo com fallback retrocompatível) ------------------------
TARGET_REPOS_RAW="${TARGET_REPOS:-}"
[[ -z "$TARGET_REPOS_RAW" ]] && TARGET_REPOS_RAW="$LEGACY_REPO"
mapfile -t ALL_REPOS < <(printf '%s\n' "$TARGET_REPOS_RAW" | tr ',' '\n' \
  | awk '{for(i=1;i<=NF;i++) if(!seen[$i]++) print $i}')
(( ${#ALL_REPOS[@]} )) || die "nenhum alvo definido (TARGET_REPOS/TARGET_REPO)"
for _r in "${ALL_REPOS[@]}"; do
  [[ "$_r" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "alvo inválido em TARGET_REPOS: '$_r'"
done
unset _r

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

# Converte o formato legado (single-alvo) para o dict multi-alvo, atribuindo a
# trilha existente ao TARGET_REPO antigo. stdin → stdout; entrada inválida ⇒ {}.
migrate_state() {
  local raw
  raw="$(cat 2>/dev/null || true)"
  if [[ -z "$raw" ]] || ! jq -e . <<<"$raw" >/dev/null 2>&1; then
    echo '{}'; return 0
  fi
  jq --arg legacy "$LEGACY_REPO" '
    if (.visibility | type) == "string" then
      {($legacy): {visibility: .visibility, public_since: .public_since, last_push: .last_push}}
    else . end' <<<"$raw"
}

json_or_null() { # ''|'null' → null; caso contrário → string JSON quotada
  if [[ -z "${1:-}" || "${1:-}" == null ]]; then echo null; else printf '"%s"' "$1"; fi
}

save_state() { # save_state <json-dict> — 1 commit; re-merge semântico se push concorrente
  local json="$1"
  printf '%s\n' "$json" > "$STATE_FILE.tmp"
  if [[ -f "$STATE_FILE" ]] && jq -e . "$STATE_FILE" >/dev/null 2>&1 \
     && diff -q <(jq -S . "$STATE_FILE") <(jq -S . "$STATE_FILE.tmp") >/dev/null; then
    rm -f "$STATE_FILE.tmp"; log "estado inalterado — sem commit"; return 0
  fi
  mv "$STATE_FILE.tmp" "$STATE_FILE"
  git add "$STATE_FILE"
  git commit -qm "state(${MODE}): $(printf '%s' "$json" | jq -rS 'to_entries|map("\(.key)=\(.value.visibility)")|join(",")')"
  local attempt remote merged
  for attempt in 1 2 3; do
    if git push -q origin "$STATE_BRANCH"; then
      log "estado persistido no branch ${STATE_BRANCH}"; return 0
    fi
    # Sentinela e guardas correm em PARALELO pós-multi-alvo: ambas commitam no
    # branch `state`. Push rejeitado ⇒ mescla a versão remota com a nossa
    # (nossas entradas vencem por repo) e repete o push.
    log "push do estado rejeitado (concorrência) — mesclando com remoto (tentativa ${attempt})"
    git fetch -q origin "$STATE_BRANCH"
    remote="$(git show "FETCH_HEAD:$STATE_FILE" 2>/dev/null | migrate_state || true)"
    [[ -n "$remote" ]] || remote='{}'
    merged="$(jq -S -n --argjson a "$remote" --argjson b "$json" '$a * $b')"
    git reset -q --soft FETCH_HEAD
    printf '%s\n' "$merged" > "$STATE_FILE"
    git add "$STATE_FILE"
    git commit -qm "state(${MODE}): mescla concorrente do branch state"
  done
  die "não foi possível persistir estado no branch ${STATE_BRANCH}"
}

iso_to_epoch() { date -u -d "${1:?}" +%s; }
now_epoch()    { date -u +%s; }

# ---- Leitura do alvo --------------------------------------------------------
fetch_target() { # fetch_target <owner/name>
  local repo="${1:?repo obrigatório}"
  TARGET_JSON="$(api GET "/repos/${repo}")" \
    || die "não foi possível ler ${repo}"
  TARGET_PRIVATE="$(jq -r '.private' <<<"$TARGET_JSON")"
  TARGET_PUSHED="$(jq -r '.pushed_at' <<<"$TARGET_JSON")"
  [[ "$TARGET_PRIVATE" == true ]] && TARGET_VIS=private || TARGET_VIS=public
}

get_repo_field() { # get_repo_field <repo> <campo> — do estado persistido (migrado)
  load_state | migrate_state | jq -r --arg k "$1" --arg f "$2" '.[$k][$f] // empty'
}

persist_repo() { # persist_repo <repo> <vis> <public_since|null|''> <last_push>
  local new
  new="$(load_state | migrate_state | jq --arg k "$1" --arg v "$2" \
    --argjson ps "$(json_or_null "$3")" --arg lp "$4" \
    '.[$k] = {visibility:$v, public_since:$ps, last_push:$lp}')"
  save_state "$new"
}

open_issue() { # open_issue <titulo> <corpo>
  if [[ -n "${GH_TOKEN:-}" ]]; then
    GH_TOKEN="$GH_TOKEN" gh issue create -R "$WATCHDOG_REPO" \
      --title "$1" --body "$2" >/dev/null 2>&1 || true
  fi
}

# ============================================================================
# MODE=detect — sentinela de transições (todos os alvos)
# ============================================================================
do_detect() {
  # Fase 1 — leitura integral (fail-closed: qualquer erro aborta ANTES de agir)
  local -A vis_of push_of
  local repo
  for repo in "${ALL_REPOS[@]}"; do
    fetch_target "$repo"
    vis_of["$repo"]="$TARGET_VIS"
    push_of["$repo"]="$TARGET_PUSHED"
  done

  # Fase 2 — compara com o estado persistido (migrado) e arma guardas
  local new_state prev public_since ps_out
  new_state="$(load_state | migrate_state)"
  for repo in "${ALL_REPOS[@]}"; do
    prev="$(jq -r --arg k "$repo" '.[$k].visibility // empty' <<<"$new_state")"
    public_since="$(jq -r --arg k "$repo" '.[$k].public_since // empty' <<<"$new_state")"
    log "alvo=${repo} vis=${vis_of[$repo]} prev=${prev:-<none>} pushed_at=${push_of[$repo]}"
    if [[ "${vis_of[$repo]}" == public && "$prev" != public ]]; then
      log "TRANSIÇÃO CAPTURADA: privado ➞ público — armando guarda de inatividade (${INACTIVITY_MINUTES} min)"
      ps_out="$(date -u +%FT%TZ)"
      if [[ -n "${GH_TOKEN:-}" ]]; then
        GH_TOKEN="$GH_TOKEN" gh workflow run guard.yml -R "$WATCHDOG_REPO" \
          -f target="$repo" -f inactivity_minutes="$INACTIVITY_MINUTES" \
        && log "guard.yml disparado para ${repo}" || log "WARN: falha ao disparar guard.yml para ${repo} (cron o cobrirá)"
      fi
    elif [[ "${vis_of[$repo]}" == private && "$prev" == public ]]; then
      log "transição público ➞ privado registrada (manual ou guarda)"
      ps_out=null
    elif [[ "${vis_of[$repo]}" == public ]]; then
      ps_out="${public_since:-$(date -u +%FT%TZ)}"   # preserva abertura conhecida
    else
      ps_out=null
    fi
    new_state="$(jq --arg k "$repo" --arg v "${vis_of[$repo]}" \
      --argjson ps "$(json_or_null "$ps_out")" --arg lp "${push_of[$repo]}" \
      '.[$k] = {visibility:$v, public_since:$ps, last_push:$lp}' <<<"$new_state")"
  done

  # Fase 3 — persistência ÚNICA do ciclo (migração inclusa)
  save_state "$new_state"
}

# ============================================================================
# MODE=guard — inatividade ➞ reconversão verificada
# ============================================================================
active_runs_count() { # active_runs_count <repo>
  # Runs ativas RECENTES = entregas reais em andamento. Runs queued/in_progress
  # há mais de ACTIVE_RUN_MAX_AGE_MIN (default 45) são zumbis (ex.: dependabot
  # dinâmico travado) e NÃO adiam a reconversão.
  local runs now
  runs="$(api GET "/repos/${1:?}/actions/runs?per_page=100")"
  now="$(now_epoch)"
  jq --argjson now "$now" --argjson max_age $(( ${ACTIVE_RUN_MAX_AGE_MIN:-45} * 60 )) '
    [.workflow_runs[]
      | select(.status == "in_progress" or .status == "queued")
      | select(($now - (.created_at | sub("\\.[0-9]+Z$"; "Z") | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime)) < $max_age)]
    | length' <<<"$runs"
}

guard_repo() { # guard_repo <repo> — 0=ok/nada-a-fazer; 1=conversão não confirmada
  local repo="$1"
  fetch_target "$repo"
  if [[ "$TARGET_VIS" == private ]]; then
    log "[${repo}] já privado — nada a fazer (estado padrão ✔)"
    persist_repo "$repo" private null "$TARGET_PUSHED"
    return 0
  fi

  local public_since ps_epoch pushed_epoch ref_epoch idle_min runs attempt ok=false
  public_since="$(get_repo_field "$repo" public_since)"
  [[ -z "$public_since" ]] && public_since="$(date -u +%FT%TZ)"  # primeira observação

  # ESPERA ATIVA INLINE: o schedule do GitHub (free) sofre jitter alto (ticks
  # irregulares); este run NÃO depende de novo tick — aguarda até o limite de
  # inatividade (com folga) e converte no mesmo run.
  while :; do
    fetch_target "$repo"   # revalida: janela pode ter sido fechada manualmente
    if [[ "$TARGET_VIS" == private ]]; then
      log "[${repo}] fechado manualmente durante a espera — registrado"
      persist_repo "$repo" private null "$TARGET_PUSHED"
      return 0
    fi

    pushed_epoch=0
    [[ -n "$TARGET_PUSHED" && "$TARGET_PUSHED" != null ]] && pushed_epoch="$(iso_to_epoch "$TARGET_PUSHED")"
    ps_epoch="$(iso_to_epoch "$public_since")"
    ref_epoch=$(( pushed_epoch > ps_epoch ? pushed_epoch : ps_epoch ))
    idle_min=$(( ( $(now_epoch) - ref_epoch ) / 60 ))
    (( idle_min >= INACTIVITY_MINUTES )) && break
    if (( $(now_epoch) >= DEADLINE )); then
      log "[${repo}] deadline de espera atingido — próxima guarda (cron/dispatch) converte, idle=${idle_min}min"
      persist_repo "$repo" public "$public_since" "$TARGET_PUSHED"
      return 0
    fi
    log "[${repo}] aguardando: inatividade ${idle_min}/${INACTIVITY_MINUTES} min (espera ativa neste run)"
    persist_repo "$repo" public "$public_since" "$TARGET_PUSHED" || true
    sleep 60
  done

  log "[${repo}] público desde ${public_since}; inatividade ${idle_min} min ≥ limite ${INACTIVITY_MINUTES}"

  # fail-safe: não interromper CI ativo (runs recentes; zumbis >45min não contam)
  while :; do
    runs="$(active_runs_count "$repo")"
    (( runs == 0 )) && break
    if (( $(now_epoch) >= DEADLINE )); then
      log "[${repo}] ADIADO definitivo: ${runs} run(s) ativa(s) e deadline esgotado — próximo tick converte"
      return 0
    fi
    log "[${repo}] ADIADO: ${runs} run(s) de CI ativa(s) — não interromper entregas (esperando)"
    sleep 60
  done

  if [[ "$DRY_RUN" == true ]]; then
    log "[${repo}] DRY_RUN: converteria ${repo} para privado agora"; return 0
  fi

  log "[${repo}] inativo ≥ ${INACTIVITY_MINUTES} min — convertendo público ➞ privado"
  for attempt in 1 2 3; do
    api PATCH "/repos/${repo}" '{"private":true}' >/dev/null
    sleep 3
    fetch_target "$repo"
    if [[ "$TARGET_VIS" == private ]]; then ok=true; break; fi
    log "[${repo}] tentativa ${attempt}: conversão não confirmada, repetindo"
  done
  if [[ "$ok" != true ]]; then
    open_issue "[watchdog] FALHA: ${repo} segue público" \
      "Guarda não confirmou a reconversão após 3 tentativas. Verificar manualmente."
    log "FATAL: reconversão de ${repo} NÃO confirmada — issue crítica aberta"
    return 1
  fi

  log "VERIFICADO via API: ${repo} privado ✔ (attempt ${attempt})"
  persist_repo "$repo" private null "$TARGET_PUSHED"
  log "[${repo}] ciclo completo: público ➞ privado ➞ testado ➞ validado ✔"
}

do_guard() {
  # Deadline do RUN (não por repo): início + (N+10) min — por isso a guarda
  # dedicada por repo (dispatch da sentinela com target=<repo>) dá paralelismo
  # real; o caminho sem target (cron) itera TARGET_REPOS como rede de segurança.
  DEADLINE=$(( $(now_epoch) + (INACTIVITY_MINUTES + 10) * 60 ))
  local repo failed=0
  if [[ -n "$GUARD_TARGET" ]]; then
    guard_repo "$GUARD_TARGET" || failed=1
  else
    for repo in "${ALL_REPOS[@]}"; do
      guard_repo "$repo" || failed=1
    done
  fi
  if (( failed )); then
    die "guarda falhou para ≥1 repo — issue(s) crítica(s) aberta(s)"
  fi
}

# ----------------------------------------------------------------------------
git config user.name  "${GIT_AUTHOR_NAME:-watchdog-bot}"
git config user.email "${GIT_AUTHOR_EMAIL:-watchdog-bot@users.noreply.github.com}"

case "$MODE" in
  detect) sync_state_branch; do_detect ;;
  guard)  sync_state_branch; do_guard ;;
  *) die "uso: watchdog.sh [detect|guard]" ;;
esac
