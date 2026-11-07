# Офлайн-анализ firmware

Ни один основной инструмент проекта не обновляет flash. Файлы HP, установщики Windows и извлечённые образы не распространяются в этом репозитории. Получайте оригинальные файлы у HP и сохраняйте их вне Git. Контрольные суммы двух исследованных контейнеров и main-образов находятся в [official-engine-images.json](../tools/firmware/official-engine-images.json).

## Сборка строгого CAB-экстрактора

Нужны C-компилятор, make и заголовки/библиотека libmspack; на Debian это `build-essential libmspack-dev`.

```bash
make extractor
build/extract-engine /path/to/extracted/Data1.cab /private/DJ500_A.04.02.fmw
```

Экстрактор принимает только настоящий CAB с сигнатурой MSCF, извлекает единственный `DJ500_A.04.02.fmw` и проверяет ошибки libmspack. EXE/MSI сначала нужно разобрать контейнерным инструментом, например 7-Zip: CAB-поток внутри MSI Compound хранится секторами, поэтому вырезать непрерывный участок EXE по сигнатуре неверно. Установщик не запускается; repair/игнорирование контрольных сумм не включаются.

`CPPFLAGS` и `LDLIBS` в Makefile позволяют использовать отдельно установленную libmspack. В репозитории нет её заголовков, библиотек или исходников.

## Проверка контейнера и регистраций Tcl

```bash
python - <<'PY'
import sys,json
sys.path.insert(0,'tools/firmware')
from inspect_firmware import inspect
result=inspect('/private/DJ500_A.04.02.fmw')
print(json.dumps(result,indent=2))
PY
```

Инспектор требует известный SHA256, проверяет контейнерную checksum и zlib, затем находит ссылки регистрации команд. Checksum/CRC не доказывает подлинность поставщика; цепочка получения файла у HP проверяется отдельно. Наличие `fpSimulateKey` в образе не означает разрешения вызывать её или готового безопасного управления.

Для карты read-only PML:

```bash
python tools/service/extract_pml_objects.py /private/engine-A0402-main.bin > /private/pml-map.json
```

74 статических дескриптора не означают 74 испытанных SNMP-объекта на живом JetDirect. Генератор отмечает это в результате. Для дополнительной дизассемблировки `readback_map.py` нужен отдельно установленный Capstone 5; vendored-библиотеки не включены.

Полная интеграционная проверка официальных образов запускается так:

```bash
HP_PLOTTER_FIXTURES=/private/firmware make test
```

В каталоге должны лежать `DJ500_A.04.02.fmw` и `DJ500_A.05.01.fmw`. Без них этот тест явно пропускается; остальные тесты работают с искусственными данными и эмулятором USB.
