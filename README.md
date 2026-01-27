# FG-api (FortiGate Firewall Policy Exporter)

## Назначение

-   Получение firewall policies с FortiGate через FortiOS REST API
-   Фильтрация policies по заданным критериям
-   Экспорт результата в CSV
-   Управление поведением исключительно через `.env`

------------------------------------------------------------------------

## Требования

-   Python 3.9+
-   Доступ к FortiGate REST API
-   API Token с правами на CMDB (firewall policy)
-   FortiGate FortiOS 6.x / 7.x

------------------------------------------------------------------------

## Установка

### 1. Клонировать репозиторий

``` bash
git clone <repo_url>
cd FG-api
```

### 2. Создать виртуальное окружение

``` bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate    # Windows
```

### 3. Установить зависимости

``` bash
pip install -r requirements.txt
```

------------------------------------------------------------------------

## Первичная настройка

### 1. Создать `.env`

``` bash
cp .env.example .env
```

### 2. Заполнить обязательные параметры

``` dotenv
FGT_API_TOKEN=
FGT_API_BASE_URL=https://<fortigate>/api/v2
FGT_VDOM=
```

### 3. (Опционально) Отключить проверку TLS

``` dotenv
FGT_VERIFY_TLS=false
```

------------------------------------------------------------------------

## Управление фильтрацией

Фильтры применяются **клиентской логикой** (после получения данных).\
Если значение пустое --- фильтр не применяется.

``` dotenv
FILTER_SRCINTF=
FILTER_DSTINTF=
FILTER_ACTION=
FILTER_STATUS=
FILTER_NAME=
FILTER_POLICYID=
FILTER_SRCADDR=
FILTER_DSTADDR=
FILTER_SERVICE=
```

### Серверная фильтрация (FortiOS)

``` dotenv
FGT_SERVER_FILTER=srcintf==port1
```

------------------------------------------------------------------------

## Управление выводом

### CSV (основной результат)

``` dotenv
EXPORT_CSV=true
CSV_FILENAME=firewall_policies.csv
OUTPUT_DIR=./output
```

### Консоль (опционально)

``` dotenv
PRINT_CONSOLE=false
OUTPUT_MAX_COL_WIDTH=80
```

### Управление полями (SHOW\_\*)

``` dotenv
SHOW_POLICYID=true
SHOW_NAME=true
SHOW_SRCINTF=true
SHOW_DSTINTF=true
SHOW_SRCADDR=true
SHOW_DSTADDR=true
SHOW_SERVICE=true
SHOW_ACTION=true
SHOW_STATUS=true
SHOW_SCHEDULE=false
SHOW_LOGTRAFFIC=false
```

CSV автоматически адаптируется под выбранные поля.

------------------------------------------------------------------------

## Запуск

``` bash
python main.py
```

Результат: - CSV файл в директории `output/` - Имя файла задаётся через
`CSV_FILENAME` или генерируется автоматически

------------------------------------------------------------------------

## Отладка

``` dotenv
DEBUG=true
DEBUG_RESPONSE_KEYS=true
DEBUG_RESULTS_TYPE=true
```

В debug-режиме выводится: - Итоговый URL запроса - HTTP статус -
Структура ответа FortiGate - Тип и размер `results`

------------------------------------------------------------------------

## Структура проекта (ключевые элементы)

    FG-api/
    ├── main.py
    ├── fgpol/
    │   ├── config.py
    │   ├── client.py
    │   ├── filters.py
    │   ├── fields.py
    │   ├── fortios.py
    │   ├── exporters.py
    │   └── table.py
    ├── output/
    │   └── .gitkeep
    ├── .env.example
    └── requirements.txt

------------------------------------------------------------------------

## Версия

-   v1.0
