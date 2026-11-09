"""A small output check, not a cleaning routine or proof of physical K isolation.

Optional local dependency: reportlab. Uses the bundled OFL font.
"""
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import argparse,hashlib,json

parser=argparse.ArgumentParser(description='Create one 610 x 100 mm black-output check PDF; never sends it to a printer.')
parser.add_argument('output',type=Path)
args=parser.parse_args()
font=Path(__file__).resolve().parents[1]/'service/assets/IBMPlexSans-Regular.ttf'
pdfmetrics.registerFont(TTFont('Plex',str(font)))
p=args.output
if p.exists():parser.error('output already exists; choose another path')
c=canvas.Canvas(str(p),pagesize=(610*mm,100*mm),pageCompression=1)
c.setTitle('Проверка вывода чёрного — 610 × 100 мм')
c.setAuthor('HP Plotter Lab')
def label(x,y,text,size=10):
 c.setFillColorCMYK(1,0,0,0);c.setFont('Plex',size);c.drawString(x*mm,y*mm,text)
label(175,85,'ПРОВЕРКА ЧЁРНОГО · один лист 610 × 100 мм',13)
label(175,77,'Квадрат, линии и градации. Подписи голубые, чтобы видеть начало теста.',9)
c.setFillColorCMYK(0,0,0,1);c.rect(175*mm,45*mm,20*mm,20*mm,stroke=0,fill=1)
label(175,39,'100% чёрный',9)
c.setStrokeColorCMYK(0,0,0,1);c.setLineWidth(.25*mm)
for i in range(11):
 x=(210+i*2)*mm;y=(45+i*2)*mm
 c.line(x,45*mm,x,65*mm);c.line(210*mm,y,230*mm,y)
label(210,39,'Сетка 2 мм',9)
for i,tone in enumerate((1,.75,.5,.25)):
 x=245+i*24
 c.setFillColorCMYK(0,0,0,tone);c.rect(x*mm,45*mm,18*mm,20*mm,stroke=0,fill=1)
 label(x,39,f'{int(tone*100)}%',9)
c.setFillColorCMYK(0,0,0,1);c.rect(175*mm,24*mm,160*mm,3*mm,stroke=0,fill=1)
label(175,15,'Внешняя проверка печати. Не является автоматической прочисткой головки.',9)
label(175,9,'Если видны только голубые подписи — чёрные элементы не вышли.',9)
c.showPage();c.save();p.chmod(0o600)
print(json.dumps({'file':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'page_mm':[610,100],'pages':1,'copies':1,'input_black':'DeviceCMYK K only; driver may convert to RGB','physical_K_isolation_proven':False},ensure_ascii=False))
