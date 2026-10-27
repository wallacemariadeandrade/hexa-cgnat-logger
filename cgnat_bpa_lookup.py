#!/usr/bin/env python3
"""
CGNAT BPA lookup: dado IP pÃºblico + porta + horÃ¡rio, encontra o assinante
(IP privado) a partir dos eventos NAT gravados pelo nfcapd.

Funciona com records NSEL e NEL/IPFIX (ex.: A10 Thunder), em qualquer
versÃ£o do nfdump 1.7.x:
  - evento NAT lido pelo cÃ³digo numÃ©rico (o -o raw pode imprimir
    "1: ADD" ou "1: NAT translation create", dependendo da versÃ£o);
  - horÃ¡rio: "Event time" -> "first" -> "received at" (ignorando
    campos zerados / 1970);
  - horÃ¡rios comparados em epoch (sem depender do fuso do servidor).
"""
import argparse
import json
import os
import re
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9
    ZoneInfo = None

# ---------------------------------------------------------------- parsing raw
REC_START = re.compile(r"^\s*Flow Record:\s*$")
KV_LINE = re.compile(r"^\s*([a-zA-Z0-9 _-]+?)\s*=\s*(.*?)\s*$")

# CÃ³digos IANA natEvent (IE 230) -> ADD / DELETE
ADD_CODES = {1, 4, 6, 8, 10, 14, 16}      # create / BIB create / addr bind / PBA alloc
DEL_CODES = {2, 5, 7, 9, 11, 15, 17}      # delete / BIB delete / addr unbind / PBA dealloc
ADD_WORDS = re.compile(r"\b(ADD\w*|create|allocation)\b", re.I)
DEL_WORDS = re.compile(r"\b(DEL\w*|delete|de-allocation)\b", re.I)


def parse_raw_records(raw: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    current: Optional[Dict[str, str]] = None
    for line in raw.splitlines():
        if REC_START.match(line):
            if current:
                records.append(current)
            current = {}
            continue
        if current is None:
            continue
        m = KV_LINE.match(line)
        if not m:
            continue
        key = re.sub(r"\s+", " ", m.group(1).strip().lower().replace("-", " "))
        current.setdefault(key, m.group(2).strip())
    if current:
        records.append(current)
    return records


def get_nat_event(rec: Dict[str, str]) -> Optional[str]:
    v = rec.get("nat event")
    if not v:
        return None
    m = re.match(r"\s*(\d+)", v)
    if m:
        code = int(m.group(1))
        if code in ADD_CODES:
            return "ADD"
        if code in DEL_CODES:
            return "DELETE"
    # fallback pelo texto (DEL testado antes: "de-allocation" contÃ©m "allocation")
    if DEL_WORDS.search(v):
        return "DELETE"
    if ADD_WORDS.search(v):
        return "ADD"
    return None


def get_int(rec: Dict[str, str], key: str) -> Optional[int]:
    v = rec.get(key)
    if not v:
        return None
    m = re.search(r"(-?\d+)", v)
    return int(m.group(1)) if m else None


def get_msec(rec: Dict[str, str], key: str) -> Optional[int]:
    """Retorna o epoch em ms do campo (nÃºmero antes do [..]); None se zero/ausente."""
    v = rec.get(key)
    if not v:
        return None
    m = re.match(r"\s*(\d+)", v)
    if not m:
        return None
    ms = int(m.group(1))
    # < 2000-01-01: campo zerado ou lixo (o famoso 1970)
    return ms if ms >= 946684800000 else None


def event_time(rec: Dict[str, str]) -> Tuple[Optional[int], str]:
    for key in ("event time", "first", "received at"):
        ms = get_msec(rec, key)
        if ms is not None:
            return ms, key
    return None, ""


def compute_block_end(start: int, size: int, step: int) -> int:
    return start + (size - 1) * step


def port_in_block(port: int, start: int, size: int, step: int) -> bool:
    end = compute_block_end(start, size, step)
    if port < start or port > end:
        return False
    if step <= 1:
        return True
    return ((port - start) % step) == 0


SessionKey = Tuple[str, str, int, int, int]  # (priv, pub, pstart, psize, pstep)


def extract_key(rec: Dict[str, str]) -> Optional[Tuple[SessionKey, int, str, str]]:
    ev = get_nat_event(rec)
    if not ev:
        return None
    priv = rec.get("src addr")
    pub = rec.get("src xlt ip")
    if not (priv and pub):
        return None

    pstart = get_int(rec, "pblock start")
    pend = get_int(rec, "pblock end")
    psize = get_int(rec, "pblock size")
    pstep = get_int(rec, "pblock step") or 1

    if pstart is not None and not psize and pend:
        psize = (pend - pstart) // pstep + 1
    if pstart is None or not psize:
        xport = get_int(rec, "src xlt port")
        if xport:  # evento de sessÃ£o: porta Ãºnica
            pstart, psize, pstep = xport, 1, 1
        else:      # binding de endereÃ§o sem portas: bloco inteiro
            pstart, psize, pstep = 0, 65536, 1

    ms, src = event_time(rec)
    if ms is None:
        return None
    key: SessionKey = (priv.strip(), pub.strip(), pstart, psize, pstep)
    return key, ms, ev, src


# ------------------------------------------------- arquivos por horÃ¡rio no nome
FNAME_RE = re.compile(r"^nfcapd\.(\d{12})$")  # YYYYMMDDHHMM


def list_nfcapd_files(dirpath: str) -> List[Tuple[int, str]]:
    """(epoch_ms, path). O nome do arquivo estÃ¡ no fuso local do servidor."""
    items: List[Tuple[int, str]] = []
    for name in os.listdir(dirpath):
        m = FNAME_RE.match(name)
        if not m:
            continue
        st = time.strptime(m.group(1), "%Y%m%d%H%M")
        items.append((int(time.mktime(st) * 1000), os.path.join(dirpath, name)))
    items.sort(key=lambda x: x[0])
    return items


def closest_index(files: List[Tuple[int, str]], when_ms: int) -> int:
    """Ãndice mais Ã  direita com inÃ­cio <= when_ms (0 se nenhum)."""
    idx = 0
    lo, hi = 0, len(files) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if files[mid][0] <= when_ms:
            idx = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return idx


# ------------------------------------------------------------------ nfdump
FILTER_CANDIDATES = ["src nat ip {ip}", "xip {ip}", "src xlate ip {ip}"]
_filter_tpl: Optional[str] = None


def _nfdump(filepath: str, filter_expr: str) -> Tuple[int, str]:
    p = subprocess.run(["nfdump", "-r", filepath, "-o", "raw", filter_expr],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout


def run_nfdump_file(filepath: str, pub: str) -> str:
    global _filter_tpl
    tpls = [_filter_tpl] if _filter_tpl else FILTER_CANDIDATES
    last_out = ""
    for tpl in tpls:
        rc, out = _nfdump(filepath, tpl.format(ip=pub))
        if rc == 0 or "No matching flows" in out:
            _filter_tpl = tpl
            return out
        last_out = out
    raise RuntimeError(f"Erro rodando nfdump em {filepath}:\n{last_out}")


# ------------------------------------------------------------------ helpers
def tz_of(name: str):
    if name.upper() == "UTC":
        return timezone.utc
    if ZoneInfo is None:
        raise SystemExit("Python sem zoneinfo; use --tz UTC ou Python >= 3.9")
    return ZoneInfo(name)


def fmt_ms(ms: int, tz) -> str:
    return datetime.fromtimestamp(ms / 1000, tz).strftime("%Y-%m-%d %H:%M:%S.") + f"{ms % 1000:03d}"


def save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(
        description="CGNAT BPA lookup (NSEL e NEL/IPFIX) sem usar -t; varre nfcapd.* pelo nome.")
    ap.add_argument("--dir", default="/var/cache/nfdump", help="DiretÃ³rio dos nfcapd.*")
    ap.add_argument("--pub", required=True, help="IP pÃºblico (src xlt ip)")
    ap.add_argument("--port", required=True, type=int, help="Porta pÃºblica")
    ap.add_argument("--time", required=True, help='HorÃ¡rio "YYYY-mm-dd HH:MM:SS" no fuso de --tz')
    ap.add_argument("--tz", default="America/Sao_Paulo",
                    help="Fuso do --time e do relatÃ³rio (padrÃ£o America/Sao_Paulo; use UTC se preciso)")
    ap.add_argument("--lookback-days", type=int, default=60)
    ap.add_argument("--lookahead-days", type=int, default=60)
    ap.add_argument("--slack-min", type=int, default=15,
                    help="Minutos de folga: eventos podem chegar ao coletor atrasados (padrÃ£o 15)")
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    tz = tz_of(args.tz)
    when_dt = datetime.strptime(args.time, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
    when = int(when_dt.timestamp() * 1000)
    # o ofÃ­cio informa sÃ³ atÃ© o segundo: "00:40:40" cobre de 00:40:40.000 a 00:40:40.999
    when_end = when + 999
    slack = args.slack_min * 60_000
    os.makedirs(args.outdir, exist_ok=True)

    audit: Dict[str, Any] = {
        "query": {"pub": args.pub, "port": args.port, "time": args.time, "tz": args.tz,
                  "time_utc": fmt_ms(when, timezone.utc)},
        "params": {"dir": args.dir, "lookback_days": args.lookback_days,
                   "lookahead_days": args.lookahead_days, "slack_min": args.slack_min},
        "scanned": {"back_files": 0, "forward_files": 0},
        "result": {},
    }

    files = list_nfcapd_files(args.dir)
    if not files:
        print("NÃ£o achei nenhum arquivo nfcapd.* no diretÃ³rio.")
        return

    # ordem total dos eventos: (epoch_ms, Ã­ndice do arquivo, Ã­ndice do record)
    # -> resolve ADD/DELETE repetidos no mesmo milissegundo
    Order = Tuple[int, int, int]

    # ---------------- BACKWARD: Ãºltimo ADD <= when cujo bloco contÃ©m a porta
    lookback_limit = when - args.lookback_days * 86_400_000
    best: Optional[Tuple[Order, SessionKey, str]] = None

    i = closest_index(files, when + slack)
    while i >= 0 and files[i][0] >= lookback_limit - slack:
        audit["scanned"]["back_files"] += 1
        raw = run_nfdump_file(files[i][1], args.pub)
        for r, rec in enumerate(parse_raw_records(raw)):
            ext = extract_key(rec)
            if not ext:
                continue
            key, ms, ev, src = ext
            if ev != "ADD" or key[1] != args.pub or ms > when_end:
                continue
            if not port_in_block(args.port, key[2], key[3], key[4]):
                continue
            order = (ms, i, r)
            if best is None or order > best[0]:
                best = (order, key, src)
        # para cedo sÃ³ quando o ADD Ã© mais antigo que o arquivo atual menos a folga,
        # garantindo que nenhum arquivo anterior tenha um ADD mais recente
        if best is not None and files[i][0] <= best[0][0] - slack:
            break
        i -= 1

    stamp = when_dt.strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(args.outdir, f"cgnat_report_{args.pub}_{args.port}_{stamp}.txt")
    audit_path = os.path.join(args.outdir, f"cgnat_audit_{args.pub}_{args.port}_{stamp}.json")
    audit["filter_used"] = _filter_tpl

    def both(ms: int) -> str:
        return f"{fmt_ms(ms, tz)} ({args.tz})  |  {fmt_ms(ms, timezone.utc)} UTC"

    header = [
        "RELATÃ“RIO DE CORRELAÃ‡ÃƒO CGNAT (BPA)",
        "",
        f"Consulta: {args.pub}:{args.port} em {fmt_ms(when, tz)} ({args.tz})"
        f"  |  {fmt_ms(when, timezone.utc)} UTC",
        "",
    ]
    # o Ãºltimo arquivo cobre ~5 min a partir do horÃ¡rio do nome
    data_until = files[-1][0] + 5 * 60_000
    future_note = []
    if when > data_until:
        future_note = [
            f"ATENÃ‡ÃƒO: o horÃ¡rio consultado Ã© posterior aos logs disponÃ­veis "
            f"(Ãºltimo arquivo: {both(files[-1][0])}). Confira data, hora e fuso.",
            "",
        ]

    def finish(status: str, body: List[str]) -> None:
        report = header + [f"RESULTADO: {status}", ""] + body + future_note + [
            "Obs: o script nÃ£o usa -t porque records EVENT podem ter first/last zerados e o -t nÃ£o casa.",
            "",
        ]
        report_txt = "\n".join(report)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_txt)
        save_json(audit_path, audit)
        print(report_txt)
        print(f"RelatÃ³rio salvo em: {report_path}")
        print(f"Auditoria salva em: {audit_path}")
        # linha de mÃ¡quina: lida pela pÃ¡gina PHP para colorir o resultado
        print(f"STATUS={audit['result']['status']}")

    if best is None:
        audit["result"] = {"status": "SEM_REGISTRO", "error": "no_add_found"}
        finish("NENHUM REGISTRO ENCONTRADO", [
            f"NÃ£o hÃ¡ alocaÃ§Ã£o (ADD) do IP {args.pub} com a porta {args.port} "
            f"nos {args.lookback_days} dias anteriores ao horÃ¡rio consultado.",
            "",
        ])
        return

    add_order, best_key, add_src = best
    add_time = add_order[0]

    # ---------------- FORWARD: primeiro DELETE do mesmo bloco depois do ADD
    # comeÃ§a no arquivo do ADD (um DELETE antes do horÃ¡rio consultado invalida o vÃ­nculo)
    lookahead_limit = when + args.lookahead_days * 86_400_000
    deleted: Optional[Tuple[Order, str]] = None

    j = max(0, closest_index(files, add_time) - 1)
    while j < len(files) and files[j][0] <= lookahead_limit:
        audit["scanned"]["forward_files"] += 1
        raw = run_nfdump_file(files[j][1], args.pub)
        for r, rec in enumerate(parse_raw_records(raw)):
            ext = extract_key(rec)
            if not ext:
                continue
            k2, ms, ev, src = ext
            if ev != "DELETE" or k2 != best_key:
                continue
            order = (ms, j, r)
            if order <= add_order:
                continue
            if deleted is None or order < deleted[0]:
                deleted = (order, src)
        if deleted is not None and files[j][0] >= deleted[0][0] + slack:
            break
        j += 1

    del_time = deleted[0][0] if deleted else None
    valid = when_end >= add_time and (del_time is None or when <= del_time)

    priv, pub, pstart, psize, pstep = best_key
    pend = compute_block_end(pstart, psize, pstep)
    approx = [n for n, s in (("ADD", add_src), ("DELETE", deleted[1] if deleted else ""))
              if s == "received at"]
    del_txt = both(del_time) if del_time else "sem DELETE registrado (vÃ­nculo ainda ativo ou fora do lookahead)"

    vinculo = [
        f"  IP privado: {priv}",
        f"  IP pÃºblico: {pub}",
        f"  Bloco BPA:  {pstart}-{pend} (size={psize}, step={pstep})",
        f"  ADD:        {both(add_time)}",
        f"  DELETE:     {del_txt}",
        "",
    ]
    if approx:
        vinculo += [f"ATENÃ‡ÃƒO: horÃ¡rio de {', '.join(approx)} veio do 'received at' do coletor "
                    "(o exportador nÃ£o enviou timestamp do evento); pode estar atrasado alguns minutos.", ""]

    audit["result"] = {
        "status": "IDENTIFICADO" if valid else "SEM_ASSINANTE",
        "valid_at_time": valid,
        ("best" if valid else "last_holder_context"): {
            "priv": priv, "pub": pub,
            "pblock_start": pstart, "pblock_size": psize, "pblock_step": pstep,
            "add_time_utc": fmt_ms(add_time, timezone.utc), "add_time_source": add_src,
            "del_time_utc": fmt_ms(del_time, timezone.utc) if del_time else None,
            "del_time_source": deleted[1] if deleted else None,
        },
    }

    if valid:
        finish("ASSINANTE IDENTIFICADO", vinculo)
    else:
        finish("NENHUM ASSINANTE COM ESSE BLOCO NO HORÃRIO CONSULTADO", [
            f"O Ãºltimo vÃ­nculo do bloco que contÃ©m a porta {args.port} foi encerrado",
            "ANTES do horÃ¡rio consultado, e nÃ£o houve nova alocaÃ§Ã£o atÃ© esse horÃ¡rio.",
            "",
            "---- Apenas contexto: NÃƒO Ã© o assinante do horÃ¡rio consultado ----",
            "Ãšltimo titular do bloco antes do horÃ¡rio consultado:",
        ] + vinculo)


if __name__ == "__main__":
    main()

