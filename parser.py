import pandas as pd
from bs4 import BeautifulSoup
import httpx
import asyncio
import re
import time
from googletrans import Translator
import nest_asyncio

# Применяем nest_asyncio, если вы работаете в Jupyter или другой среде с циклом событий
nest_asyncio.apply()

start_time = time.time()

# Инициализируем переводчик
translator = Translator()

# Шаг 1: Прочитать HTML-файл
with open('ScanOval.html', 'r', encoding='utf-8') as file:
    soup = BeautifulSoup(file, 'html.parser')

# Шаг 2: Извлечь данные из таблицы
data = []
capec_data = []  # Новый список для хранения CAPEC ID и описаний
capec_set = set()  # Множество для хранения уникальных CAPEC ID
table = soup.find('thead').find_next('table') 
rows = table.find_all('tr')[1:]  # Пропускаем заголовок

# Словари для кэширования
cwe_cache = {}
capec_cache = {}

MAX_CONCURRENT_REQUESTS = 6
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

# Общее количество BDU ID для отображения в счетчике
total_bdu_ids = sum(len(cols[0].text.replace('BDU:', '').strip()) // 10 for row in rows for cols in [row.find_all('td')] if len(cols) >= 3)

# Счетчик выполненных запросов
request_counter = 0

async def fetch(url):
    async with httpx.AsyncClient(verify=False) as client:
        for attempt in range(5):  # Попробуйте 5 раз
            try:
                response = await client.get(url, timeout=30.0)
                response.raise_for_status()  # Это вызовет HTTPError для статусов 4xx/5xx
                return response.text, response.status_code
            except httpx.ReadTimeout:
                print(f"Тайм-аут при запросе к {url}.")
            except httpx.HTTPError as e:  # Обработка ошибок HTTP
                print(f"Ошибка HTTP {e.response.status_code} при запросе к {url}.")
            except Exception as e:
                print(f"Ошибка при запросе к {url}: {e}")
            
            await asyncio.sleep(2)  # Задержка перед повторной попыткой
        print(f"Не удалось получить ответ от {url} после 5 попыток.")
        return None, None

async def fetch_capec_data(capec_id):
    if capec_id in capec_cache:
        return capec_cache[capec_id]  # Возвращаем кэшированные данные

    capec_number = re.search(r'CAPEC-(\d+)', capec_id).group(1)
    capec_url = f'https://capec.mitre.org/data/definitions/{capec_number}.html'
    print("Запрос к ", capec_url)
    
    html, status = await fetch(capec_url)
    if status == 200 and html:
        soup = BeautifulSoup(html, 'html.parser')
        likelihood_div = soup.find(id="Likelihood_Of_Attack")
        if likelihood_div:
            likelihood = likelihood_div.find(class_="detail").get_text(strip=True)
            capec_cache[capec_id] = likelihood  # Сохраняем в кэш
            return likelihood
    return None

async def process_row(row):
    global request_counter  # Используем глобальную переменную для счетчика
    async with semaphore:
        cols = row.find_all('td')
        if len(cols) >= 3:
            bdu_ids = cols[0].text.replace('BDU:', '').strip()
            vulnerability_name = cols[2].text.strip()
            
            bdu_ids = [bdu_ids[i:i+10] for i in range(0, len(bdu_ids), 10)]
            
            for bdu_id in bdu_ids:
                link = f'https://bdu.fstec.ru/vul/{bdu_id}'
                print("Запрос URL: " + link)
                
                html, status = await fetch(link)
                request_counter += 1  # Увеличиваем счетчик запросов
                print(f"{request_counter} из {total_bdu_ids} запросов выполнено.")  # Выводим текущий статус

                if status == 200 and html:
                    page_soup = BeautifulSoup(html, 'html.parser')
                    json_data_element = page_soup.find('script', string=re.compile(r'const v_model ='))
                    if json_data_element:
                        json_text = json_data_element.string
                        cwe_match = re.search(r'"cwe_id":"(\d+)"', json_text)
                        if cwe_match:
                            cwe_id = f"CWE-{cwe_match.group(1)}"
                            link_cwe = f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html"

                            if cwe_id in cwe_cache:
                                likelihoods = cwe_cache[cwe_id]
                            else:
                                cwe_html, cwe_status = await fetch(link_cwe)
                                if cwe_status == 200 and cwe_html:
                                    cwe_soup = BeautifulSoup(cwe_html, 'html.parser')
                                    capec_ids = []
                                    capec_table = cwe_soup.find('div', {'name': re.compile(r'Related_Attack_Patterns')})
                                    if capec_table:
                                        capec_rows = capec_table.find_all('tr')[1:]  # Пропускаем заголовок
                                        for capec_row in capec_rows:
                                            capec_cells = capec_row.find_all('td')
                                            if len(capec_cells) >= 2:
                                                capec_id = capec_cells[0].text.strip()  # CAPEC ID из первого столбца
                                                description = capec_cells[1].text.strip()  # Описание из второго столбца
                                                
                                                # Добавляем только уникальные CAPEC ID
                                                if capec_id not in capec_set:
                                                    capec_set.add(capec_id)
                                                    capec_data.append({'CAPEC ID': capec_id, 'Description': description})  # Сохраняем CAPEC ID и описание
                                                    capec_ids.append(capec_id)

                                    # Извлекаем Вероятность атаки
                                    likelihoods = {
                                        "High": [],
                                        "Medium": [],
                                        "Low": [],
                                        "Не найден": []
                                    }

                                    # Параллельный парсер для CAPEC
                                    capec_tasks = [fetch_capec_data(capec_id) for capec_id in capec_ids]
                                    capec_results = await asyncio.gather(*capec_tasks)

                                    for capec_id, likelihood in zip(capec_ids, capec_results):
                                        if likelihood:
                                            likelihoods[likelihood].append(capec_id)
                                        else:
                                            likelihoods["Не найден"].append(capec_id)

                                    # Сохраняем результаты в кэш
                                    cwe_cache[cwe_id] = likelihoods

                            # Добавляем данные в список
                            data.append({
                                'BDU ID': bdu_id,
                                'Vulnerability Name': vulnerability_name,
                                'CWE ID': cwe_id if 'cwe_id' in locals() else "Не найдено",
                                'CAPEC IDs (High)': "\n".join(likelihoods["High"]) if likelihoods["High"] else "Не найдено",
                                'CAPEC IDs (Medium)': "\n".join(likelihoods["Medium"]) if likelihoods["Medium"] else "Не найдено",
                                'CAPEC IDs (Low)': "\n".join(likelihoods["Low"]) if likelihoods["Low"] else "Не найдено",
                                'CAPEC IDs (Не найден)': "\n".join(likelihoods["Не найден"]) if likelihoods["Не найден"] else "Не найдено",
                            })

async def main():
    tasks = [process_row(row) for row in rows]  # Обрабатываем все строки
    await asyncio.gather(*tasks)

# Запуск асинхронного парсера
asyncio.run(main())

# Шаг 4: Перевод описаний CAPEC перед записью в файл
print("Перевод описаний CAPEC на русский язык...")
for capec in capec_data:
    capec['Description'] = translator.translate(capec['Description'], dest='ru').text

# Запись результатов в Excel
print("Запись в файл...")
df = pd.DataFrame(data)
df.to_excel('BDU_DATA.xlsx', index=False)
print("Данные успешно записаны в файл BDU_DATA.xlsx")

# Запись CAPEC данных в отдельный файл
capec_df = pd.DataFrame(capec_data)
capec_df.to_excel('CAPEC_DATA.xlsx', index=False)
print("Данные CAPEC успешно записаны в файл CAPEC_DATA.xlsx")

# Вывод времени выполнения
end_time = time.time()
print(f"Время выполнения: {end_time - start_time:.2f} секунд")

