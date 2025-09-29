import json
import random
import time
import os
import requests

# ---------- Конфигурация ----------
TARGET = "http://127.0.0.1:3000/rest/products/24/reviews"  # поменяй на свою тестовую цель
SEED_FILE = "seed.json"       # должен быть валидный пример запроса
OUT_DIR = "fuzz_reports"      # куда сохраняем интересные payload'ы
ITERATIONS = 200              # сколько запросов сделать
TIMEOUT = 5.0                 # таймаут HTTP запроса
SLOW_FACTOR = 3.0             # помечаем как "медленный", если rt > baseline * SLOW_FACTOR
KEYWORDS = ["exception", "traceback", "error", "segfault", "nullpointer"]
RANDOM_SEED = 42              # фиксируем для воспроизводимости
# ----------------------------------

random.seed(RANDOM_SEED)
os.makedirs(OUT_DIR, exist_ok=True)

def load_seed(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def simple_mutate(obj):
    """
    Простые мутации:
     - для строк: пустая строка, длинная строка, вставка спецсимволов
     - для int: 0, -1, очень большое число
     - для list: добавить длинную строку
    """
    out = json.loads(json.dumps(obj))  # глубокая копия простым способом
    # выбираем случайный ключ (работаем с top-level словарём)
    if not isinstance(out, dict):
        return out
    k = random.choice(list(out.keys()))
    v = out[k]
    if isinstance(v, str):
        op = random.choice(["empty","long","weird"])
        if op == "empty":
            out[k] = ""
        elif op == "long":
            out[k] = v + "A" * random.randint(200, 2000)
        else:  # weird
            # вставляем несколько не ASCII символов и нулей
            out[k] = v + "\x00" + "".join(chr(random.randint(0x80,0xFF)) for _ in range(10))
    elif isinstance(v, int):
        out[k] = random.choice([0, -1, 2**31-1, 2**63-1])
    elif isinstance(v, list):
        out[k].append("A" * random.randint(100, 800))
    else:
        out[k] = None
    return out

def measure_baseline(seed, samples=5):
    """Простой baseline по времени ответа."""
    times = []
    for _ in range(samples):
        try:
            t0 = time.time()
            r = requests.post(TARGET, json=seed, timeout=TIMEOUT)
            times.append(time.time() - t0)
        except Exception:
            times.append(TIMEOUT)
    return sum(times) / len(times)

def is_interesting(resp_code, resp_text, rt, baseline_rt):
    """Критерии 'interesting' — расширяй по необходимости."""
    if resp_code == "ERR":
        return True, ["network_error"]
    if isinstance(resp_code, int) and resp_code >= 500:
        return True, [f"http_{resp_code}"]
    if rt > baseline_rt * SLOW_FACTOR:
        return True, ["slow_response"]
    lower = resp_text.lower()
    for kw in KEYWORDS:
        if kw in lower:
            return True, [f"body_contains_{kw}"]
    return False, []

def save_interesting(payload_obj, meta):
    """Сохраняем полный payload + метаинфу в файл для триажа."""
    stamp = int(time.time() * 1000)
    fname = os.path.join(OUT_DIR, f"interesting_{stamp}.json")
    data = {"meta": meta, "payload": payload_obj}
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return fname

def main():
    seed = load_seed(SEED_FILE)
    baseline_rt = measure_baseline(seed)
    print(f"[+] Baseline RTT = {baseline_rt:.3f}s (SLOW_FACTOR={SLOW_FACTOR})")

    interesting_count = 0
    for i in range(ITERATIONS):
        payload = simple_mutate(seed)
        t0 = time.time()
        try:
            r = requests.post(TARGET, json=payload, timeout=TIMEOUT)
            rt = time.time() - t0
            code = r.status_code
            body = r.text[:2000]
        except Exception as e:
            rt = time.time() - t0
            code = "ERR"
            body = str(e)

        interesting, reasons = is_interesting(code, body, rt, baseline_rt)
        tag = "INTERESTING" if interesting else "ok"
        print(f"[{i+1}/{ITERATIONS}] {tag} code={code} rt={rt:.3f}s len={len(body)} reasons={reasons}")
        if interesting:
            interesting_count += 1
            meta = {"index": i, "code": code, "rt": rt, "reasons": reasons}
            fname = save_interesting(payload, meta)
            print(f"    -> saved {fname}")

    print(f"[+] Done. Total interesting: {interesting_count}/{ITERATIONS}")

if __name__ == "__main__":
    main()
