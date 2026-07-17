#!/usr/bin/env python3
"""
Web Parameter Fuzzer - Инструмент для тестирования веб-параметров
Только для образовательных целей и тестирования с разрешения!
"""

import requests
from bs4 import BeautifulSoup
import urllib.parse
from typing import List, Dict, Set
import time
import random
import argparse
import sys

class WebParameterFuzzer:
    def __init__(self, base_url: str, delay: float = 0.5, timeout: int = 10):
        self.base_url = base_url
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        
        # Безопасные полезные нагрузки
        self.payloads = [
            # Специальные символы
            "../../",
            "\\..\\",
            "<!--",
            "../",
            "..\\",
            
            # Пустые и специальные значения
            "",
            "null",
            "undefined",
            "true",
            "false",
            "0",
            "1",
            
            # Длинные строки
            "A" * 500,
            "A" * 1000,
            "A" * 2000,
            
            # Специальные символы
            "%00",
            "%0A",
            "%0D",
            "%20",
            "%2F",
            "\\",
            "/",
            ".",
            "..",
            "...",
            
            # Unicode символы
            "тест",
            "测试",
            "😀",
            "★",
            "✓",
            
            # HTML теги
            "<b>test</b>",
            "<i>test</i>",
            "<u>test</u>",
            "<br>",
            
            # JavaScript
            "alert(1)",
            "console.log(1)",
            
            # SQL
            "' OR '1'='1",
            "' UNION SELECT 1,2,3",
            "1' ORDER BY 1",
            "SELECT * FROM users",
            "INSERT INTO users VALUES (1,2,3)",
            
            # Команды
            "echo test",
            "ls -la",
            "ping 1.1.1.1",
            "pwd",
            "id",
        ]
        
        # Заголовки User-Agent для ротации
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36",
        ]

    def extract_parameters_from_url(self, url: str) -> Dict[str, str]:
        """Извлечение параметров из URL"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return {key: values[0] for key, values in params.items() if values}

    def extract_forms(self, url: str) -> List[Dict]:
        """Извлечение всех форм со страницы"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name', ''),
                        'value': input_tag.get('value', '')
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
            
            return forms
            
        except Exception as e:
            print(f"[!] Ошибка при извлечении форм: {e}")
            return []

    def fuzz_url_parameters(self, url: str) -> Dict[str, List[Dict]]:
        """Фаззинг параметров URL"""
        results = {'vulnerabilities': []}
        base_params = self.extract_parameters_from_url(url)
        
        if not base_params:
            print("[-] Не найдено параметров для фаззинга")
            return results
        
        print(f"\n[+] Найдено параметров: {len(base_params)}")
        
        for param_name, original_value in base_params.items():
            print(f"\n[+] Фаззинг параметра: {param_name}")
            
            for payload in self.payloads:
                try:
                    fuzzed_params = base_params.copy()
                    fuzzed_params[param_name] = payload
                    
                    parsed_url = urllib.parse.urlparse(url)
                    fuzzed_query = urllib.parse.urlencode(fuzzed_params)
                    fuzzed_url = urllib.parse.urlunparse(
                        parsed_url._replace(query=fuzzed_query)
                    )
                    
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    response = self.session.get(fuzzed_url, headers=headers, timeout=self.timeout)
                    
                    vulnerability = self.analyze_response(
                        response, param_name, payload, original_value
                    )
                    
                    if vulnerability:
                        results['vulnerabilities'].append(vulnerability)
                        print(f"[!] Найдена аномалия: {vulnerability['type']}")
                    
                    time.sleep(self.delay)
                    
                except requests.exceptions.Timeout:
                    print(f"[!] Таймаут для параметра {param_name} с payload: {payload[:30]}...")
                except Exception as e:
                    print(f"[-] Ошибка: {e}")
        
        return results

    def fuzz_forms(self, url: str) -> Dict[str, List[Dict]]:
        """Фаззинг HTML форм"""
        results = {'vulnerabilities': []}
        forms = self.extract_forms(url)
        
        if not forms:
            print("[!] Не найдено форм для фаззинга")
            return results
        
        print(f"\n[+] Найдено форм: {len(forms)}")
        
        for form_idx, form in enumerate(forms):
            print(f"\n[+] Фаззинг формы #{form_idx + 1}")
            
            form_url = form['action']
            if not form_url.startswith('http'):
                form_url = urllib.parse.urljoin(url, form_url)
            
            for input_field in form['inputs']:
                if not input_field['name']:
                    continue
                    
                print(f"[+] Фаззинг поля: {input_field['name']}")
                
                for payload in self.payloads:
                    try:
                        form_data = {}
                        for field in form['inputs']:
                            if field['name']:
                                if field['name'] == input_field['name']:
                                    form_data[field['name']] = payload
                                else:
                                    form_data[field['name']] = field['value']
                        
                        headers = {'User-Agent': random.choice(self.user_agents)}
                        
                        if form['method'] == 'post':
                            response = self.session.post(
                                form_url, 
                                data=form_data, 
                                headers=headers,
                                timeout=self.timeout
                            )
                        else:
                            response = self.session.get(
                                form_url, 
                                params=form_data, 
                                headers=headers,
                                timeout=self.timeout
                            )
                        
                        vulnerability = self.analyze_response(
                            response, input_field['name'], payload, input_field['value']
                        )
                        
                        if vulnerability:
                            vulnerability['form_index'] = form_idx
                            results['vulnerabilities'].append(vulnerability)
                            print(f"[+] Найдена аномалия: {vulnerability['type']}")
                        
                        time.sleep(self.delay)
                        
                    except requests.exceptions.Timeout:
                        print(f"[!] Таймаут для поля {input_field['name']}")
                    except Exception as e:
                        print(f"[-] Ошибка: {e}")
        
        return results

    def analyze_response(self, response: requests.Response, param_name: str, 
                        payload: str, original_value: str) -> Dict:
        """Анализ ответа на наличие аномалий"""
        vulnerability = None
        content = response.text.lower()
        status_code = response.status_code
        
        # Проверка на ошибки SQL
        sql_indicators = [
            "sql syntax", "mysql", "ora-", "microsoft odbc", 
            "postgresql", "sqlite", "warning: mysql",
            "sql error", "database error"
        ]
        
        if any(indicator in content for indicator in sql_indicators):
            vulnerability = {
                'type': 'SQL Error',
                'parameter': param_name,
                'payload': payload,
                'status_code': status_code,
                'response_length': len(response.content)
            }
        
        # Проверка на ошибки сервера
        elif status_code >= 500:
            vulnerability = {
                'type': 'Server Error',
                'parameter': param_name,
                'payload': payload,
                'status_code': status_code,
                'response_length': len(response.content)
            }
        
        # Проверка на ошибки 404
        elif status_code == 404:
            vulnerability = {
                'type': 'Not Found',
                'parameter': param_name,
                'payload': payload,
                'status_code': status_code,
                'response_length': len(response.content)
            }
        
        # Проверка на странную длину ответа
        elif len(response.content) > 100000:
            vulnerability = {
                'type': 'Large Response (Possible Data Leak)',
                'parameter': param_name,
                'payload': payload,
                'status_code': status_code,
                'response_length': len(response.content)
            }
        
        # Проверка на ошибки отладки
        elif any(indicator in content for indicator in ["traceback", "exception", "debug", "error in"]):
            vulnerability = {
                'type': 'Debug Information',
                'parameter': param_name,
                'payload': payload,
                'status_code': status_code,
                'response_length': len(response.content)
            }
        
        return vulnerability

    def run_fuzzing(self, include_forms: bool = True, include_url_params: bool = True) -> Dict:
        """Запуск полного процесса фаззинга"""
        print(f"\n[+] Запуск фаззинга для: {self.base_url}")
        print(f"[+] Задержка между запросами: {self.delay}с")
        print(f"[+] Таймаут: {self.timeout}с")
        print("-" * 60)
        
        results = {
            'url': self.base_url,
            'url_parameters_results': {},
            'forms_results': {},
            'summary': {}
        }
        
        # Фаззинг параметров URL
        if include_url_params:
            print("\n=== Фаззинг параметров URL ===")
            results['url_parameters_results'] = self.fuzz_url_parameters(self.base_url)
        
        # Фаззинг форм
        if include_forms:
            print("\n=== Фаззинг HTML форм ===")
            results['forms_results'] = self.fuzz_forms(self.base_url)
        
        # Сводка
        url_vulns = results['url_parameters_results'].get('vulnerabilities', [])
        form_vulns = results['forms_results'].get('vulnerabilities', [])
        total_vulns = len(url_vulns) + len(form_vulns)
        
        results['summary'] = {
            'total_findings': total_vulns,
            'url_parameters_findings': len(url_vulns),
            'forms_findings': len(form_vulns),
            'url_params_tested': len(self.extract_parameters_from_url(self.base_url))
        }
        
        print("\n" + "=" * 60)
        print("[+] СВОДКА")
        print("=" * 60)
        print(f"Всего найдено аномалий: {total_vulns}")
        print(f"В параметрах URL: {results['summary']['url_parameters_findings']}")
        print(f"В формах: {results['summary']['forms_findings']}")
        print("=" * 60)
        
        return results

def parse_args():
    parser = argparse.ArgumentParser(
        description="Web Parameter Fuzzer - Безопасный инструмент для тестирования веб-параметров",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python web_fuzzer.py -u "https://example.com/test.php?id=1"
  python web_fuzzer.py -u "https://example.com/search?q=test" -d 0.5 -t 15
  python web_fuzzer.py -u "http://localhost:3000/products?id=1" --no-forms
        """
    )
    
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Целевой URL для тестирования"
    )
    
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.5,
        help="Задержка между запросами в секундах (по умолчанию: 0.5)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Таймаут HTTP запроса в секундах (по умолчанию: 10)"
    )
    
    parser.add_argument(
        "--no-forms",
        action="store_true",
        help="Не тестировать HTML формы"
    )
    
    parser.add_argument(
        "--no-url-params",
        action="store_true",
        help="Не тестировать параметры URL"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод"
    )
    
    return parser.parse_args()

def main():
    args = parse_args()
     
    fuzzer = WebParameterFuzzer(args.url, delay=args.delay, timeout=args.timeout)
    results = fuzzer.run_fuzzing(
        include_forms=not args.no_forms,
        include_url_params=not args.no_url_params
    )
    
    if args.verbose and results['summary']['total_findings'] > 0:
        print("\n[+] Детали найденных аномалий:")
        for vuln_type in ['url_parameters_results', 'forms_results']:
            for vulnerability in results[vuln_type]['vulnerabilities']:
                print(f"\n- Тип: {vulnerability['type']}")
                print(f"  Параметр: {vulnerability['parameter']}")
                print(f"  Payload: {vulnerability['payload'][:100]}")
                print(f"  Status: {vulnerability['status_code']}")
                print(f"  Длина ответа: {vulnerability['response_length']} bytes")

if __name__ == "__main__":
    main()