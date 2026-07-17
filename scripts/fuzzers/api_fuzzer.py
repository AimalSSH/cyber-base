#!/usr/bin/env python3
"""
Fuzzer для REST API с мутационным тестированием.
Генерирует "интересные" payload'ы и сохраняет их для дальнейшего анализа.
"""

import json
import random
import time
import os
import requests
import argparse
import sys

# ---------- Конфигурация по умолчанию ----------
DEFAULT_TARGET = "http://127.0.0.1:3000/rest/products/24/reviews"
DEFAULT_SEED = "seed.json"
DEFAULT_OUT_DIR = "fuzz_reports"
DEFAULT_ITERATIONS = 200
DEFAULT_TIMEOUT = 5.0
DEFAULT_SLOW_FACTOR = 3.0
DEFAULT_KEYWORDS = ["exception", "traceback", "error", "segfault", "nullpointer"]
DEFAULT_RANDOM_SEED = 42
# -----------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="API Fuzzer - мутационное тестирование REST эндпоинтов",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python fuzzer.py -t http://localhost:3000/api/test -s seed.json -n 100
  python fuzzer.py -t https://example.com/api -s payload.json -o reports -n 500
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        default=DEFAULT_TARGET,
        help=f"Целевой URL (по умолчанию: {DEFAULT_TARGET})"
    )
    
    parser.add_argument(
        "-s", "--seed",
        default=DEFAULT_SEED,
        help=f"Файл с seed payload (JSON) (по умолчанию: {DEFAULT_SEED})"
    )
    
    parser.add_argument(
        "-o", "--out-dir",
        default=DEFAULT_OUT_DIR,
        help=f"Директория для сохранения отчетов (по умолчанию: {DEFAULT_OUT_DIR})"
    )
    
    parser.add_argument(
        "-n", "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"Количество итераций (по умолчанию: {DEFAULT_ITERATIONS})"
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Таймаут HTTP запроса в секундах (по умолчанию: {DEFAULT_TIMEOUT})"
    )
    
    parser.add_argument(
        "--slow-factor",
        type=float,
        default=DEFAULT_SLOW_FACTOR,
        help=f"Множитель для определения медленных ответов (по умолчанию: {DEFAULT_SLOW_FACTOR})"
    )
    
    parser.add_argument(
        "--seed-value",
        type=int,
        default=DEFAULT_RANDOM_SEED,
        help=f"Значение для random.seed (по умолчанию: {DEFAULT_RANDOM_SEED})"
    )
    
    parser.add_argument(
        "--keywords",
        nargs="+",
        default=DEFAULT_KEYWORDS,
        help=f"Ключевые слова для поиска в ответе (по умолчанию: {DEFAULT_KEYWORDS})"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод (лог всех payload'ов)"
    )
    
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Не сохранять интересные payload'ы (только логировать)"
    )
    
    return parser.parse_args()

def load_seed(path):
    """Загрузка seed JSON из файла."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Ошибка: файл {path} не найден")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Ошибка: невалидный JSON в {path}: {e}")
        sys.exit(1)

def simple_mutate(obj):
    """
    Простые мутации:
     - для строк: пустая строка, длинная строка, вставка спецсимволов
     - для int: 0, -1, очень большое число
     - для list: добавить длинную строку
    """
    out = json.loads(json.dumps(obj))
    if not isinstance(out, dict):
        return out
    
    # Выбираем случайный ключ
    k = random.choice(list(out.keys()))
    v = out[k]
    
    if isinstance(v, str):
        op = random.choice(["empty", "long", "weird"])
        if op == "empty":
            out[k] = ""
        elif op == "long":
            out[k] = v + "A" * random.randint(200, 2000)
        else:  # weird
            out[k] = v + "\x00" + "".join(chr(random.randint(0x80, 0xFF)) for _ in range(10))
    elif isinstance(v, int):
        out[k] = random.choice([0, -1, 2**31-1, 2**63-1, -2**31])
    elif isinstance(v, list):
        out[k].append("A" * random.randint(100, 800))
    else:
        out[k] = None
    return out

def measure_baseline(seed, samples=5, timeout=5.0):
    """Простой baseline по времени ответа."""
    times = []
    for _ in range(samples):
        try:
            t0 = time.time()
            r = requests.post(TARGET, json=seed, timeout=timeout)
            times.append(time.time() - t0)
        except Exception:
            times.append(timeout)
    return sum(times) / len(times)

def is_interesting(resp_code, resp_text, rt, baseline_rt, slow_factor, keywords):
    """Критерии 'interesting'."""
    if resp_code == "ERR":
        return True, ["network_error"]
    if isinstance(resp_code, int) and resp_code >= 500:
        return True, [f"http_{resp_code}"]
    if rt > baseline_rt * slow_factor:
        return True, ["slow_response"]
    lower = resp_text.lower()
    for kw in keywords:
        if kw in lower:
            return True, [f"body_contains_{kw}"]
    return False, []

def save_interesting(payload_obj, meta, out_dir):
    """Сохраняем полный payload + метаинфу в файл для триажа."""
    stamp = int(time.time() * 1000)
    fname = os.path.join(out_dir, f"interesting_{stamp}.json")
    data = {"meta": meta, "payload": payload_obj}
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return fname

def main():
    args = parse_args()
    
    # Настройка
    global TARGET
    TARGET = args.target
    SEED_FILE = args.seed
    OUT_DIR = args.out_dir
    ITERATIONS = args.iterations
    TIMEOUT = args.timeout
    SLOW_FACTOR = args.slow_factor
    KEYWORDS = args.keywords
    RANDOM_SEED = args.seed_value
    VERBOSE = args.verbose
    NO_SAVE = args.no_save
    
    random.seed(RANDOM_SEED)
    os.makedirs(OUT_DIR, exist_ok=True)
    
    print(f"[+] Target: {TARGET}")
    print(f"[+] Seed file: {SEED_FILE}")
    print(f"[+] Output dir: {OUT_DIR}")
    print(f"[+] Iterations: {ITERATIONS}")
    print(f"[+] Random seed: {RANDOM_SEED}")
    print("-" * 60)
    
    seed = load_seed(SEED_FILE)
    baseline_rt = measure_baseline(seed, timeout=TIMEOUT)
    print(f"[+] Baseline RTT = {baseline_rt:.3f}s (SLOW_FACTOR={SLOW_FACTOR})")
    print("-" * 60)
    
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
        
        interesting, reasons = is_interesting(code, body, rt, baseline_rt, SLOW_FACTOR, KEYWORDS)
        tag = "⚠️ INTERESTING" if interesting else "✓ OK"
        
        if VERBOSE or interesting:
            print(f"[{i+1}/{ITERATIONS}] {tag} code={code} rt={rt:.3f}s len={len(body)} reasons={reasons}")
            if interesting:
                print(f"    -> Payload: {json.dumps(payload, ensure_ascii=False)[:200]}...")
        else:
            # Минимальный вывод для неинтересных запросов
            if (i + 1) % 10 == 0:
                print(f"[{i+1}/{ITERATIONS}] Progress: {interesting_count} interesting so far")
        
        if interesting:
            interesting_count += 1
            meta = {
                "index": i, 
                "code": code, 
                "rt": rt, 
                "reasons": reasons,
                "target": TARGET
            }
            if not NO_SAVE:
                fname = save_interesting(payload, meta, OUT_DIR)
                print(f"    -> Saved: {fname}")
    
    print("-" * 60)
    print(f"[+] Done. Total interesting: {interesting_count}/{ITERATIONS} ({interesting_count/ITERATIONS*100:.1f}%)")
    if not NO_SAVE:
        print(f"[+] Reports saved to: {OUT_DIR}/")

if __name__ == "__main__":
    main()