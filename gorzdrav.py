#!/usr/bin/env python3
"""gorzdrav — ловец талонов «Горздрав СПб» (gorzdrav.spb.ru) с автозаписью.

Только стандартная библиотека Python 3.9+. TLS проверяется всегда: сайт подписан цепочкой Минцифры,
корень лежит в certs/russian_trusted_root_ca.pem, отпечаток сверяется при старте.
Команды отмены записи в инструменте нет и не будет.

Чтение (в Горздрав ничего не пишет):
  gorzdrav districts
  gorzdrav lpus [--district N] [--find "№27"]
  gorzdrav specs --lpu ID
  gorzdrav doctors --lpu ID --spec ID
  gorzdrav slots --lpu ID --doctor ID [--limit N]
  gorzdrav patient --lpu ID [--who me]        найти patientId (GET с ФИО и датой рождения)
  gorzdrav my --lpu ID [--who me]             предстоящие записи пациента
  gorzdrav goals | status

Запись:
  gorzdrav hunt [--dry-run] [--goal имя]           один цикл по целям (его запускает крон)
  gorzdrav book --lpu ID --doctor ID --slot ID [--who me] --yes
  gorzdrav arm <цель> | disarm [<цель>]

Файлы (вне git):
  ~/.config/gorzdrav/creds.json   {"patients": {"me": {"lastName","firstName","middleName","birthdate":"YYYY-MM-DD"}},
                                   "telegram_bot_token", "telegram_chat_id"}   (600)
  ~/.config/gorzdrav/goals.json   [{name, patient, lpu, speciality, doctors[], dates[from,to], weekdays[1..7],
                                    time[from,to], earlier_than, min_lead_minutes, mode: dry|live}]
  ~/.local/state/gorzdrav/        state.json, hunt.log, lock;  ~/.config/gorzdrav/STOP — рубильник
"""

import argparse
import fcntl
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta
from pathlib import Path

BASE = "https://gorzdrav.spb.ru/_api/api/v2"
CERT = Path(__file__).resolve().parent / "certs" / "russian_trusted_root_ca.pem"
CERT_SHA256 = "d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31"
CONF = Path.home() / ".config/gorzdrav"
STATE_DIR = Path.home() / ".local/state/gorzdrav"
CREDS = CONF / "creds.json"
GOALS = CONF / "goals.json"
STOP = CONF / "STOP"
STATE = STATE_DIR / "state.json"
LOG = STATE_DIR / "hunt.log"
LOCK = STATE_DIR / "lock"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130 Safari/537.36"

MIN_CYCLE_SEC = 60          # жёсткий пол между циклами hunt
PAUSE_SEC = 1.5             # пауза между запросами внутри цикла
FAIL_ALERT_AFTER = 5        # сбоев подряд до сообщения в TG
FAIL_PAUSE_MIN = 30         # пауза после серии сбоев
ARM_MIN_DRY_CYCLES = 30     # холостых циклов до боевого режима
DAILY_BOOK_CAP = 2          # записей в сутки на пациента
BENIGN_CODES = {39, 603, 616}   # нет талонов / МО не ответила / сбой МО — штатно


def out(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=1))


def die(msg, code=1):
    out({"ошибка": msg})
    sys.exit(code)


def now():
    return datetime.now().replace(microsecond=0)


# ---------- сеть ----------

def ssl_ctx():
    if not CERT.exists():
        die(f"нет корня Минцифры: {CERT}")
    pem = CERT.read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    if hashlib.sha256(der).hexdigest() != CERT_SHA256:
        die("отпечаток корневого сертификата не совпал — стоп, обходов нет")
    return ssl.create_default_context(cafile=str(CERT))


class ApiError(Exception):
    def __init__(self, msg, code=None, http=None):
        super().__init__(msg)
        self.code, self.http = code, http


class Api:
    def __init__(self):
        self.ctx = ssl_ctx()
        self.token = ""
        self.calls = 0

    def req(self, method, path, params=None, body=None, keep_token=False):
        url = f"{BASE}/{path}"
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        headers = {"User-Agent": UA, "Accept": "application/json",
                   "Origin": "https://gorzdrav.spb.ru", "Referer": "https://gorzdrav.spb.ru/service-free-schedule"}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["token"] = self.token
        if self.calls:
            time.sleep(PAUSE_SEC)
        self.calls += 1
        r = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(r, context=self.ctx, timeout=40) as resp:
                raw = resp.read()
                tok = resp.headers.get("token")
                status = resp.status
        except urllib.error.HTTPError as e:
            raw, tok, status = e.read(), None, e.code
        if keep_token and tok:
            self.token = tok
        try:
            j = json.loads(raw.decode("utf-8"))
        except Exception:
            raise ApiError(f"не JSON ({status}): {raw[:200]!r}", http=status)
        if status != 200:
            raise ApiError(j.get("message") or f"HTTP {status}", code=j.get("errorCode"), http=status)
        return j

    def get(self, path, params=None, keep_token=False):
        j = self.req("GET", path, params=params, keep_token=keep_token)
        if not j.get("success"):
            raise ApiError(j.get("message") or "success=false", code=j.get("errorCode"))
        return j.get("result")


# ---------- файлы ----------

def load_json(p, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def save_json(p, obj, private=True):
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
    if private:
        os.chmod(tmp, 0o600)
    tmp.replace(p)


def creds():
    c = load_json(CREDS, None)
    if c is None:
        die(f"нет {CREDS}")
    return c


def patient_of(who):
    p = (creds().get("patients") or {}).get(who)
    if not p:
        die(f"нет пациента «{who}» в {CREDS}")
    for k in ("lastName", "firstName", "birthdate"):
        if not p.get(k):
            die(f"у пациента «{who}» не заполнено {k}")
    return p


def env(name):
    v = os.environ.get(name)
    if v:
        return v.strip()
    v = load_json(CREDS, {}).get(name.lower())
    return str(v).strip() if v else None


def tg(text):
    token, chat = env("TELEGRAM_BOT_TOKEN"), env("TELEGRAM_CHAT_ID")
    if not (token and chat):
        print(f"[tg не настроен] {text}", file=sys.stderr)
        return False
    data = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
    try:
        with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=data, timeout=20) as r:
            return json.loads(r.read()).get("ok", False)
    except Exception as e:
        print(f"[tg ошибка] {e}", file=sys.stderr)
        return False


def log(line):
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(f"{now().isoformat()} {line}\n")


# ---------- чтение ----------

def slot_view(s):
    return {"id": s.get("id"), "start": s.get("visitStart"), "room": s.get("room"),
            "num": s.get("number"), "address": s.get("address")}


def doctors(api, lpu, spec):
    return api.get(f"schedule/lpu/{lpu}/speciality/{spec}/doctors") or []


def slots(api, lpu, doc):
    return api.get(f"schedule/lpu/{lpu}/doctor/{doc}/appointments") or []


def find_patient(api, lpu, who):
    p = patient_of(who)
    bd = date.fromisoformat(p["birthdate"])
    pid = api.get("patient/search", {
        "lpuId": lpu, "lastName": p["lastName"], "firstName": p["firstName"],
        "middleName": p.get("middleName") or "", "birthdate": bd.strftime("%d.%m.%Y"),
        "birthdateValue": bd.isoformat(),
    }, keep_token=True)
    if not pid:
        raise ApiError("пациент не найден")
    st = load_json(STATE, {})
    st.setdefault("patients", {})[f"{who}@{lpu}"] = pid
    save_json(STATE, st)
    return str(pid)


def upcoming(api, lpu, pid):
    return api.get("appointments", {"lpuId": lpu, "patientId": pid}) or []


# ---------- запись ----------

def create_appointment(api, lpu, pid, who, slot):
    """Единственный пишущий запрос. Никогда не повторяется (п. 5.6 плана)."""
    p = patient_of(who)
    body = {
        "esiaId": None, "lpuId": int(lpu), "patientId": pid, "appointmentId": str(slot["id"]),
        "referralId": None, "ipmpiCardId": None, "recipientEmail": None,
        "patientLastName": p["lastName"], "patientFirstName": p["firstName"],
        "patientMiddleName": p.get("middleName") or "", "patientBirthdate": p["birthdate"],
        "room": slot.get("room"), "num": slot.get("number"), "address": slot.get("address"),
        "visitDate": slot.get("visitStart"),
    }
    log(f"POST appointment/create lpu={lpu} slot={slot['id']} start={slot.get('visitStart')}")
    j = api.req("POST", "appointment/create", body=body)
    log(f"POST result success={j.get('success')} code={j.get('errorCode')} msg={j.get('message')!r} result={j.get('result')!r}")
    return j


def create_ok(j):
    """Боевой тест 19.11.2026: успешная запись = {success: true, errorCode: 0}, поле result отсутствует."""
    return bool(j.get("success")) and not j.get("errorCode")


def appt_spec_id(a):
    """Поле специальности в ответе GET appointments (снято живьём 19.11.2026)."""
    return str((a.get("specialityRendingConsultation") or {}).get("id") or "")


def booked_today(st, who):
    today = date.today().isoformat()
    return sum(1 for b in st.get("bookings", []) if b["who"] == who and b["at"].startswith(today))


def booking_msg(who, lpu, doc_name, slot, extra=""):
    return (f"✅ Записал ({who}): {doc_name}\n{slot.get('visitStart', '').replace('T', ' ')[:16]}, "
            f"каб. {slot.get('room') or '—'}, талон {slot.get('number') or '—'}\n{slot.get('address') or ''}\n"
            f"Поликлиника lpu={lpu}. Отменить можно только руками на gorzdrav.spb.ru → «Мои записи».{extra}")


# ---------- цели ----------

def goal_matches(g, slot):
    try:
        t = datetime.fromisoformat(slot["visitStart"])
    except Exception:
        return False
    if t < now() + timedelta(minutes=g.get("min_lead_minutes", 180)):
        return False
    d = g.get("dates") or []
    if d and not (d[0] <= t.date().isoformat() <= d[-1]):
        return False
    wd = g.get("weekdays") or []
    if wd and t.isoweekday() not in wd:
        return False
    tm = g.get("time") or []
    if tm and not (tm[0] <= t.strftime("%H:%M") <= tm[-1]):
        return False
    if g.get("earlier_than") and t >= datetime.fromisoformat(g["earlier_than"]):
        return False
    return True


def run_goal(api, g, gs, st, dry):
    lpu, spec, who = g["lpu"], g["speciality"], g.get("patient", "me")
    docs = doctors(api, lpu, spec)
    want = set(map(str, g.get("doctors") or []))
    cands = []
    for d in docs:
        if want and str(d.get("id")) not in want:
            continue
        if not d.get("freeTicketCount"):
            continue
        nd = (d.get("nearestDate") or "")[:10]
        dr = g.get("dates") or []
        if dr and nd and nd > dr[-1]:
            continue
        for s in slots(api, lpu, d["id"]):
            if goal_matches(g, s):
                cands.append((s["visitStart"], d, s))
        if cands:
            break   # берём первого врача с подходящим талоном — меньше запросов
    if not cands:
        return "нет подходящих"
    cands.sort(key=lambda x: x[0])
    _, d, s = cands[0]
    doc_name = d.get("name", "")
    if dry or g.get("mode") != "live":
        key = f"{s['id']}"
        if gs.get("last_dry_found") != key:
            tg(f"🔎 [холостой] {g['name']}: нашёл бы {doc_name}, {s['visitStart'].replace('T', ' ')[:16]}, каб. {s.get('room')}")
            gs["last_dry_found"] = key
        return f"нашёл бы {s['id']} {s['visitStart']} {doc_name}"
    # боевой режим
    if booked_today(st, who) >= DAILY_BOOK_CAP:
        return "потолок записей на сегодня"
    pid = st.get("patients", {}).get(f"{who}@{lpu}") or find_patient(api, lpu, who)
    if not api.token:
        find_patient(api, lpu, who)   # нужен свежий token из ответа поиска
    mine = upcoming(api, lpu, pid)
    for a in mine:
        if appt_spec_id(a) == str(spec) and not g.get("allow_second"):
            gs["mode"] = "stopped"
            tg(f"⏹ {g['name']}: у пациента уже есть запись к этой специальности ({a.get('visitStart')}). Цель остановлена.")
            return "уже записан — стоп"
    attempts = 0
    for _, d, s in cands[:2]:
        attempts += 1
        try:
            j = create_appointment(api, lpu, pid, who, s)
        except Exception as e:
            gs["mode"] = "unknown"
            tg(f"⚠️ {g['name']}: запрос записи оборвался ({e}). Исход неизвестен — проверь «Мои записи» руками. Цель на паузе.")
            return f"исход неизвестен: {e}"
        if create_ok(j):
            gs["mode"] = "booked"
            gs["booked"] = {"slot": s["id"], "start": s["visitStart"], "doctor": d.get("name")}
            st.setdefault("bookings", []).append({"who": who, "at": now().isoformat(), "slot": s["id"], "goal": g["name"]})
            tg(booking_msg(who, lpu, d.get("name", ""), s))
            return f"ЗАПИСАН {s['id']} {s['visitStart']}"
        if j.get("errorCode") == 639 and attempts < 2:
            continue
        gs["mode"] = "stopped"
        tg(f"❌ {g['name']}: Горздрав отказал в записи: код {j.get('errorCode')}, {j.get('message')}. Цель остановлена.")
        return f"отказ {j.get('errorCode')} {j.get('message')}"
    return "талоны заняли"


def cmd_hunt(a):
    if STOP.exists():
        return out({"стоп": str(STOP)})
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    lockf = LOCK.open("w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    st = load_json(STATE, {})
    last = st.get("last_cycle")
    if last and (now() - datetime.fromisoformat(last)).total_seconds() < MIN_CYCLE_SEC:
        return out({"пропуск": f"прошло меньше {MIN_CYCLE_SEC} с с прошлого цикла"})
    if st.get("paused_until") and now() < datetime.fromisoformat(st["paused_until"]):
        return out({"пауза до": st["paused_until"]})
    st["last_cycle"] = now().isoformat()
    goals = load_json(GOALS, [])
    api = Api()
    res, failed = {}, False
    for g in goals:
        if a.goal and g["name"] != a.goal:
            continue
        gs = st.setdefault("goals", {}).setdefault(g["name"], {})
        mode = gs.get("mode") or g.get("mode", "dry")
        if mode in ("booked", "stopped", "unknown"):
            res[g["name"]] = mode
            continue
        g = {**g, "mode": "dry" if a.dry_run else mode}
        try:
            r = run_goal(api, g, gs, st, dry=a.dry_run or mode != "live")
            if g["mode"] == "dry":
                gs["dry_cycles"] = gs.get("dry_cycles", 0) + 1
        except ApiError as e:
            if e.code in BENIGN_CODES:
                r = f"штатно: {e.code} {e}"
            else:
                r, failed = f"сбой: {e.code} {e}", True
        except Exception as e:
            r, failed = f"сбой: {e}", True
        res[g["name"]] = r
        log(f"goal={g['name']} mode={g['mode']} calls={api.calls} -> {r}")
    if failed:
        st["fails"] = st.get("fails", 0) + 1
        if st["fails"] == FAIL_ALERT_AFTER:
            st["paused_until"] = (now() + timedelta(minutes=FAIL_PAUSE_MIN)).isoformat()
            tg(f"⚠️ gorzdrav: {FAIL_ALERT_AFTER} сбоев подряд, пауза {FAIL_PAUSE_MIN} мин. Последнее: {res}")
    else:
        if st.get("fails", 0) >= FAIL_ALERT_AFTER:
            tg("✅ gorzdrav: снова работает")
        st["fails"] = 0
    day = date.today().isoformat()
    st.setdefault("daily", {}).setdefault(day, 0)
    st["daily"][day] += 1
    if st.get("alive_sent") != day and now().hour >= 10:
        prev = (date.today() - timedelta(days=1)).isoformat()
        tg(f"🫀 gorzdrav жив: вчера {st['daily'].get(prev, 0)} циклов. Цели: " +
           ", ".join(f"{k}={v.get('mode', '?')}" for k, v in st.get("goals", {}).items()))
        st["alive_sent"] = day
    save_json(STATE, st)
    out({"цикл": st["last_cycle"], "запросов": api.calls, "цели": res})


# ---------- команды ----------

def cmd_districts(a):
    out(Api().get("shared/districts"))


def cmd_lpus(a):
    api = Api()
    rows = api.get(f"shared/district/{a.district}/lpus") if a.district else api.get("shared/lpus")
    if a.find:
        f = a.find.lower()
        rows = [r for r in rows if f in json.dumps(r, ensure_ascii=False).lower()]
    out([{k: r.get(k) for k in ("id", "lpuShortName", "address", "districtId", "phone")} for r in rows])


def cmd_specs(a):
    rows = Api().get(f"schedule/lpu/{a.lpu}/specialties") or []
    out([{k: r.get(k) for k in ("id", "name", "countFreeTicket", "nearestDate", "lastDate")} for r in rows])


def cmd_doctors(a):
    rows = doctors(Api(), a.lpu, a.spec)
    out([{k: r.get(k) for k in ("id", "name", "freeTicketCount", "nearestDate", "lastDate")} for r in rows])


def cmd_slots(a):
    rows = slots(Api(), a.lpu, a.doctor)
    out({"всего": len(rows), "талоны": [slot_view(s) for s in rows[: a.limit]]})


def cmd_patient(a):
    api = Api()
    pid = find_patient(api, a.lpu, a.who)
    out({"patientId": pid, "token_получен": bool(api.token)})


def cmd_my(a):
    api = Api()
    pid = find_patient(api, a.lpu, a.who)
    out(upcoming(api, a.lpu, pid))


def cmd_goals(a):
    out(load_json(GOALS, []))


def cmd_status(a):
    st = load_json(STATE, {})
    out({k: st.get(k) for k in ("last_cycle", "fails", "paused_until", "goals", "bookings", "daily")} |
        {"STOP": STOP.exists()})


def set_goal_mode(name, mode):
    st = load_json(STATE, {})
    gs = st.setdefault("goals", {}).setdefault(name, {})
    gs["mode"] = mode
    save_json(STATE, st)


def cmd_arm(a):
    goals = {g["name"]: g for g in load_json(GOALS, [])}
    if a.goal not in goals:
        die(f"нет цели «{a.goal}» в {GOALS}")
    gs = load_json(STATE, {}).get("goals", {}).get(a.goal, {})
    need = ARM_MIN_DRY_CYCLES if not a.test else 1
    if gs.get("dry_cycles", 0) < need:
        die(f"у цели {gs.get('dry_cycles', 0)} холостых циклов, нужно {need}. Сначала gorzdrav hunt --dry-run")
    set_goal_mode(a.goal, "live")
    out({"цель": a.goal, "режим": "live", "последняя находка в холостом": gs.get("last_dry_found")})


def cmd_disarm(a):
    if a.goal:
        set_goal_mode(a.goal, "dry")
        return out({"цель": a.goal, "режим": "dry"})
    CONF.mkdir(parents=True, exist_ok=True, mode=0o700)
    STOP.touch()
    out({"стоп": str(STOP)})


def cmd_book(a):
    if not a.yes:
        die("ручная запись требует --yes")
    api = Api()
    s = next((x for x in slots(api, a.lpu, a.doctor) if str(x.get("id")) == str(a.slot)), None)
    if not s:
        die("такого свободного талона у врача сейчас нет")
    st = load_json(STATE, {})
    if booked_today(st, a.who) >= DAILY_BOOK_CAP:
        die("потолок записей на сегодня")
    pid = find_patient(api, a.lpu, a.who)
    before = upcoming(api, a.lpu, pid)
    try:
        j = create_appointment(api, a.lpu, pid, a.who, s)
    except Exception as e:
        tg(f"⚠️ ручная запись: запрос оборвался ({e}). Проверь «Мои записи».")
        die(f"исход неизвестен: {e}")
    if create_ok(j):
        st.setdefault("bookings", []).append({"who": a.who, "at": now().isoformat(), "slot": s["id"], "goal": "manual"})
        save_json(STATE, st)
        tg(booking_msg(a.who, a.lpu, f"врач {a.doctor}", s))
    out({"ответ": j, "записей_до": len(before)})


def main():
    p = argparse.ArgumentParser(prog="gorzdrav", description="Талоны Горздрава СПб: поиск и автозапись")
    sp = p.add_subparsers(dest="cmd", required=True)
    sp.add_parser("districts").set_defaults(f=cmd_districts)
    x = sp.add_parser("lpus"); x.add_argument("--district", type=int); x.add_argument("--find"); x.set_defaults(f=cmd_lpus)
    x = sp.add_parser("specs"); x.add_argument("--lpu", required=True); x.set_defaults(f=cmd_specs)
    x = sp.add_parser("doctors"); x.add_argument("--lpu", required=True); x.add_argument("--spec", required=True); x.set_defaults(f=cmd_doctors)
    x = sp.add_parser("slots"); x.add_argument("--lpu", required=True); x.add_argument("--doctor", required=True)
    x.add_argument("--limit", type=int, default=20); x.set_defaults(f=cmd_slots)
    for name, fn in (("patient", cmd_patient), ("my", cmd_my)):
        x = sp.add_parser(name); x.add_argument("--lpu", required=True); x.add_argument("--who", default="me"); x.set_defaults(f=fn)
    sp.add_parser("goals").set_defaults(f=cmd_goals)
    sp.add_parser("status").set_defaults(f=cmd_status)
    x = sp.add_parser("hunt"); x.add_argument("--dry-run", action="store_true"); x.add_argument("--goal"); x.set_defaults(f=cmd_hunt)
    x = sp.add_parser("book"); x.add_argument("--lpu", required=True); x.add_argument("--doctor", required=True)
    x.add_argument("--slot", required=True); x.add_argument("--who", default="me"); x.add_argument("--yes", action="store_true")
    x.set_defaults(f=cmd_book)
    x = sp.add_parser("arm"); x.add_argument("goal"); x.add_argument("--test", action="store_true",
                                                                       help="для разовой боевой проверки: достаточно 1 холостого цикла")
    x.set_defaults(f=cmd_arm)
    x = sp.add_parser("disarm"); x.add_argument("goal", nargs="?"); x.set_defaults(f=cmd_disarm)
    a = p.parse_args()
    try:
        a.f(a)
    except ApiError as e:
        die(f"Горздрав: {e} (code={e.code}, http={e.http})")


if __name__ == "__main__":
    main()
