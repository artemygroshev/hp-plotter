# Первичные источники и внешние компоненты

В репозитории находятся собственные инструменты/тесты проекта и выделенные примеры LCD. Дистрибутивы ОС, firmware HP, чужие SSH-ключи, raw журналы установки, libusb/libmspack/Ghostscript/CUPS/Capstone и их vendored-копии не включены. У внешних компонентов сохраняются их собственные лицензии; получайте их у соответствующих проектов.

- [USB Printer Class 1.1](https://www.usb.org/sites/default/files/usbprint11a021811.pdf): alternate, ID/status и reset.
- [HP DesignJet 500/510/800 Service Manual](https://www.laserexpressinc.com/manuals/HP/hp-dsj-500-510-800-series-service-manual.pdf): стр. 3-14 — мигающие значки головок и порядок цветов; 3-23 — группа ошибок 30–33.
- [HP: HP 11 Printhead Errors](https://support.hp.com/za-en/document/c06098737): отдельный случай новых партий HP 11 на старой firmware. Для Black C4810A указан Warranty Ends 20200401 и позднее; HP рекомендует A.05.01. Применимость к исследованной головке не подтверждена.
- [HP PJL Reference](https://h10032.www1.hp.com/ctg/Manual/bpl13208.pdf): ECHO, COMMENT и выбор языка; поддержка отдельных возможностей зависит от модели.
- [Официальный пакет HP](https://ftp.hp.com/pub/softlib/software13/printers/HP_DesignJet_500_800_FU_3.8.zip): источник исследованного A.05.01; файлы пакета не включены.
- [CUPS USB backend](https://github.com/OpenPrinting/cups/blob/master/backend/usb-libusb.c) и [USB quirks](https://github.com/OpenPrinting/cups/blob/master/backend/org.cups.usb-quirks).
- [Linux: исправление usblp при нулевом ID](https://github.com/torvalds/linux/commit/7a400c6fe3617e31e690e3f7ca37bb335e0498f3): применимость конкретному vendor kernel требует проверки; сам факт upstream-исправления её не доказывает.
- [Linux usbmon](https://www.kernel.org/doc/html/latest/usb/usbmon.html).
- [Первичный отчёт о CH340S/1156210](https://bugs.launchpad.net/bugs/1156210): потеря короткой OUT-посылки при немедленном status-control на другом экземпляре; перепроверять порядок и интервалы, не приравнивать этот случай к любому тайм-ауту.
- [libusb: асинхронный I/O и короткие пакеты](https://libusb.sourceforge.io/api-1.0/group__libusb__asyncio.html), [размеры пакетов и overflow](https://libusb.sourceforge.io/api-1.0/libusb_packetoverflow.html).
- [CUPS backend(7)](https://www.cups.org/doc/man-backend.html): аргументы, права, side/back-channel; [cupsfilter исходники v2.4.10](https://github.com/OpenPrinting/cups/blob/v2.4.10/scheduler/cupsfilter.c): конкретное формирование окружения фильтров.
- [Ghostscript cdnj500/Mode 10](https://github.com/ArtifexSoftware/ghostpdl/blob/master/devices/gdevcd8.c).
- [OpenPrinting: DesignJet 500](https://www.openprinting.org/printer/HP/HP-DesignJet_500): драйвер/PPD получать отдельно, с исходной лицензией.
- [libmspack](https://www.cabextract.org.uk/libmspack/), [libusb](https://libusb.info/), [Pillow](https://python-pillow.org/), [pexpect](https://pexpect.readthedocs.io/), [NumPy](https://numpy.org/), [Capstone](https://www.capstone-engine.org/).

Статические адреса, структуры и допустимые вызовы привязаны к конкретному проверенному образу A.04.02. Найденные строки или сходство версий не дают основания переносить адреса на другую прошивку.
