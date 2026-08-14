### ЗА ВАЙТЛИСТОМ НИКОМУ УЖЕ ПИСАТЬ НЕ НАДО 

## В репозитории находится последняя версия на момент залива (v1.3) с вырезанной "проверкой лицензии"

Хранить лицензии пользователей и сам софт в ПУБЛИЧНОМ репозитории было отличной идеей. Надеюсь автор будет продолжать и дальше публиковать свои проекты для всех бесплатно. 

## Умнейшая модель защиты за 5 долларов в день

По смыслу проверка лицензии выглядит так:

```python
from datetime import datetime

def check_access(tg_id):
    licenses = fetch_licenses()

    user = licenses.get(str(tg_id))
    if not user:
        return {"status": "not_whitelisted"}

    if not user.get("active"):
        return {"status": "revoked"}

    expires = datetime.strptime(user["expires"], "%Y-%m-%d")
    if expires < datetime.now():
        return {"status": "expired", "expires": user["expires"]}

    return {"status": "ok", "expires": user["expires"]}
```

Огромный индийский офис разработчиков создал свое детище в виде сборки ссылки из "зашифрованных" кусочков в рантайме:

```text
_get_whitelist_url
_WL_F1
_WL_F2
_WL_F3
_WL_F4
_WL_F5
_WL_F6
_WL_F7
_WL_F8
_WL_KEY2
_WL_KEY6
_WL_SHIFT4
_wl_sub_decode
base64
b64decode
fromhex
b85decode
```

Ну и в итоге получается https://raw.githubusercontent.com/guniss1/mrkt-sniper-bot/master/users-licenses.json

*Телеметрии вроде никакой нет*

### Как крякнуть какую-либо из версий самостоятельно
1. Скачайте любую из версий с оригинального репозитория - https://github.com/guniss1/mrkt-sniper-bot (.zip файл)
2. Разархивируйте файл и еще один архив, который находится в нем (видать тоже защита xD)
3. Запустите скрипт командой `python auto.py mrkt-sniper.exe`
4. Запустите `mrkt-sniper-cracked.exe`
