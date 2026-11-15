"""Make two small visual checks; never opens a printer or schedules a job.

The K page needs the separately validated TRUEBLACK job mode after filtering.
The colour page uses COLOR. Neither page is a nozzle-by-nozzle service test.
Optional dependency: reportlab; the font is bundled under its OFL licence.
"""
import argparse
import hashlib
import json
from pathlib import Path

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm


def create_checks(directory):
    directory = Path(directory)
    directory.mkdir(exist_ok=True)
    paths = [directory / 'k-patterns.pdf', directory / 'colour-control.pdf']
    if any(path.exists() for path in paths):
        raise FileExistsError('do not overwrite an earlier diagnostic source')
    font = Path(__file__).resolve().parents[1] / 'service/assets/IBMPlexSans-Regular.ttf'
    pdfmetrics.registerFont(TTFont('RecoveryPlex', str(font)))
    reports = []
    for path, mode in zip(paths, ('TRUEBLACK', 'COLOR')):
        c = canvas.Canvas(str(path), pagesize=(610 * mm, 100 * mm), pageCompression=1)
        c.setAuthor('HP Plotter Lab')
        c.setTitle('Black recovery checks: ' + mode)

        def text(x, y, value, size=10):
            c.setFont('RecoveryPlex', size)
            c.drawString(x * mm, y * mm, value)

        if mode == 'TRUEBLACK':
            c.setFillColorCMYK(0, 0, 0, 1)
            c.setStrokeColorCMYK(0, 0, 0, 1)
            text(130, 84, 'K / 01 · Линии, сетка, плотности и сплошная заливка', 13)
            text(130, 76, 'Для этого листа нужен режим TRUEBLACK. Подписи тоже чёрные.', 9)
            for i, tone in enumerate((.1, .25, .5, .75, 1)):
                x = 130 + 24 * i
                c.setFillColorCMYK(0, 0, 0, tone)
                c.rect(x * mm, 42 * mm, 16 * mm, 16 * mm, stroke=0, fill=1)
                c.setFillColorCMYK(0, 0, 0, 1)
                text(x, 36, str(round(tone * 100)) + '%', 8)
            for i, width in enumerate((.2, .5, 1)):
                c.setLineWidth(width * mm)
                c.line(265 * mm, (45 + i * 5) * mm, 305 * mm, (45 + i * 5) * mm)
            text(265, 36, '0,2 / 0,5 / 1 мм', 8)
            c.setLineWidth(.2 * mm)
            for i in range(11):
                c.line((325 + 2 * i) * mm, 42 * mm, (325 + 2 * i) * mm, 62 * mm)
                c.line(325 * mm, (42 + 2 * i) * mm, 345 * mm, (42 + 2 * i) * mm)
            text(325, 36, 'Сетка 2 мм', 8)
            c.rect(365 * mm, 42 * mm, 20 * mm, 20 * mm, stroke=0, fill=1)
            text(365, 36, 'K 100%', 8)
            text(130, 20, 'Оценить: есть ли след; есть ли разрывы; меняется ли плотность.', 9)
            text(130, 12, 'Пустой лист означает отсутствие видимых следов этого задания, а не установленную причину.', 8)
        else:
            c.setFillColorCMYK(1, 0, 0, 0)
            text(130, 84, 'C / 02 · Цветной контроль передачи и печати', 13)
            text(130, 76, 'Обычный режим COLOR. Сравните с отдельным листом K / 01.', 9)
            for i, (name, ink) in enumerate((('C', (1, 0, 0, 0)), ('M', (0, 1, 0, 0)), ('Y', (0, 0, 1, 0)))):
                x = 130 + i * 84
                c.setFillColorCMYK(*ink)
                c.setStrokeColorCMYK(*ink)
                text(x, 63, name, 12)
                c.rect(x * mm, 39 * mm, 24 * mm, 18 * mm, stroke=0, fill=1)
                c.setLineWidth(.3 * mm)
                for j in range(5):
                    c.line((x + 32) * mm, (40 + j * 3) * mm, (x + 65) * mm, (40 + j * 3) * mm)
            c.setFillColorCMYK(1, 0, 0, 0)
            text(130, 20, 'Цветные элементы проверяют видимый вывод отдельно от режима TRUEBLACK.', 9)
            text(130, 12, 'Это не доказательство физической изоляции каналов: драйвер преобразует цвета.', 8)
        c.showPage()
        c.save()
        path.chmod(0o600)
        reports.append({'file': path.name, 'bytes': path.stat().st_size,
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'page_mm': [610, 100], 'pages': 1, 'required_render_mode': mode})
    return reports


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(create_checks(parser.parse_args().directory), ensure_ascii=False, indent=2))
