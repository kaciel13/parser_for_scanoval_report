# Парсер для отчета ScanOval
#### Включает поиск всех BDU_ID и их названий по файлу отчета ScanOval.html, после парсить информацию по CWE и все CAPEC к каждому СWE вся информация записывается в файл BDU_DATA. CWE на время работы програмы сохраняются в кеш поэтому программа не парсит повторно повторяющиеся CWE. Аналогично сделано и с CAPEC. После все уникальные CAPEC записываются в файл CAPEC_DATA вместе с Description, также Description к CAPEC переводяться на русский.  
#### BDU_ID может получиться больше чем в отчете ScanOval так как там некотрые BDU объеденны в одну строко (парсер их разделяет) -->> 100 BDU парсятся за 3 минуты, если нет проблем с сайтом
### Не нужно менять количесво единовремменый запросов! (сайт не выдерживает)
## Пример работы
![изображение](https://github.com/user-attachments/assets/24aca1a2-916a-4def-a4b0-4b58e7d7a93c)

## Файлы после завершения работы
![изображение](https://github.com/user-attachments/assets/2592486d-9df9-471e-94f1-c6ece354b742)
