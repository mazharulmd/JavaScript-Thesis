"""Shared helper for the thesis table documents.

Creates an empty document from the Savonia reporting template (keeping its styles, page
setup, header and footer) and adds captioned tables that render the same in Word and
LibreOffice: fixed column grid, no inherited paragraph indent, a repeating header row,
rows that do not split, and each table kept on one page where it fits.
"""
from pathlib import Path

import docx
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / 'Thesis Template' / 'Reporting Template.docx'


class TableDocument:
    def __init__(self, template=TEMPLATE):
        self.doc = docx.Document(str(template))
        body = self.doc.element.body
        for el in list(body.iterchildren()):
            if el.tag != qn('w:sectPr'):
                body.remove(el)
        self.table_no = 0

    def heading(self, text, level=1):
        return self.doc.add_paragraph(text, style=f'Heading {level}')

    def para(self, text, size=None):
        p = self.doc.add_paragraph(text)
        if size:
            for r in p.runs:
                r.font.size = Pt(size)
        return p

    def table(self, caption, header, rows, widths, note=None):
        if len(widths) != len(header):
            raise ValueError(f'{caption}: {len(widths)} widths for {len(header)} columns')
        self.table_no += 1
        cap = self.doc.add_paragraph(f'TABLE {self.table_no}. {caption}', style='Caption')
        cap.paragraph_format.keep_with_next = True
        t = self.doc.add_table(rows=1, cols=len(header))
        t.style = self.doc.styles['Table Grid']
        for i, h in enumerate(header):
            t.rows[0].cells[i].text = ''
            t.rows[0].cells[i].paragraphs[0].add_run(str(h)).bold = True
        for row in rows:
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = str(v)
        t.rows[0]._tr.get_or_add_trPr().append(OxmlElement('w:tblHeader'))
        for row in t.rows:
            row._tr.get_or_add_trPr().append(OxmlElement('w:cantSplit'))
        t.autofit = False
        for i, col in enumerate(t._tbl.tblGrid.findall(qn('w:gridCol'))):
            col.set(qn('w:w'), str(int(Cm(widths[i]).twips)))
        last = t.rows[-1]
        for row in t.rows:
            for i, cell in enumerate(row.cells):
                cell.width = Cm(widths[i])
                for p in cell.paragraphs:
                    p.paragraph_format.keep_with_next = row is not last
                    p.paragraph_format.left_indent = Cm(0)  # template Normal style is indented
                    p.paragraph_format.first_line_indent = Cm(0)
                    p.paragraph_format.space_before = Pt(1)
                    p.paragraph_format.space_after = Pt(1)
                    for r in p.runs:
                        r.font.size = Pt(9)
        if note:
            self.para(note, size=9)
        self.doc.add_paragraph()
        return t

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.doc.save(str(path))
