#!/usr/bin/env python3
"""Builds docs/thesis/Thesis-Draft.docx (and Thesis-Draft.pdf): a complete DRAFT of the thesis
report in the Savonia reporting template.

* Starts from 'Thesis Template/Reporting Template.docx' (the original file is only read): keeps
  its styles, cover page, abstract form, section setup and numbered heading styles, and replaces
  the template's sample content.
* Every result number is read from the archived files in evaluation/results/ and the ground-truth
  manifests; nothing is typed in by hand.
* Citations use Savonia's name-year (Harvard) style. Only entries in docs/references.bib are cited;
  entries the bibliography marks as UNVERIFIED are flagged for checking in the reference list.
* LibreOffice (lo_update.py) refreshes the table of contents, list of figures and list of tables,
  and exports the PDF. A second build pass caches the refreshed lists and the page count in the .docx.

THIS IS AN AI-PRODUCED DRAFT. The author must review, verify (especially every citation against the
original source), correct and rewrite it in their own voice before submission.

Usage: python3 docs/thesis/build_thesis_draft.py   (figures: node docs/thesis/render_figures.mjs)
"""
import copy
import csv
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import docx
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from docx_tables import TableDocument  # noqa: E402

ROOT = HERE.parents[1]
TEMPLATE = ROOT / 'Thesis Template' / 'Reporting Template.docx'
OUT = HERE / 'Thesis-Draft.docx'
PDF = HERE / 'Thesis-Draft.pdf'
FIG = HERE / 'figures'
RES = ROOT / 'evaluation' / 'results'

TITLE = 'Automated Detection of Broken Access Control Vulnerabilities in REST APIs'
SUBTITLE = 'A Role-Aware Testing Tool in JavaScript'
AUTHOR = 'Md Mazharul Islam'
FIELD_OF_STUDY = 'Technology, Communication and Transport'
DEGREE_PROGRAMME = 'Degree Programme in Information Technology'
DRAFT_NOTE = ('AI-PRODUCED DRAFT - NOT FOR SUBMISSION. This text was drafted with AI assistance (Claude Code, '
              'Anthropic) from the project repository. The author must review and verify every statement, '
              'check every citation against the original source, correct errors, and rewrite the text in '
              'their own voice before submission. Placeholders in [square brackets] must be completed.')


# =============================================================================================== data
def read_json(rel):
    return json.loads((ROOT / rel).read_text())


def run_node(args):
    return subprocess.run(['node', *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


bench = read_json('evaluation/results/2026-11-21-scanner-test-api/comparison/metrics.json')
vampi = read_json('evaluation/results/2026-11-21-scanner-vampi/comparison/metrics.json')
vampi_patched = read_json('evaluation/results/2026-11-21-scanner-vampi/comparison-patched/metrics.json')
gt = read_json('test-api/ground-truth.json')
gt_sec = read_json('test-api/ground-truth.secure.json')
vgt = read_json('benchmarks/vampi/ground-truth.json')
vgt_sec = read_json('benchmarks/vampi/ground-truth.secure.json')
patched_findings = read_json('evaluation/results/2026-11-21-scanner-test-api/role-aware-patched-findings.json')
zap_runs = {
    'E1 vulnerable': read_json('evaluation/results/2026-11-20-zap-test-api/vulnerable/zap-report.json'),
    'E1 patched': read_json('evaluation/results/2026-11-20-zap-test-api/patched/zap-report.json'),
    'E2 vulnerable': read_json('evaluation/results/2026-11-20-zap-vampi/vulnerable/zap-report.json'),
    'E2 patched': read_json('evaluation/results/2026-11-20-zap-vampi/patched/zap-report.json'),
}
zap_patched_metrics = {
    'E1 patched': read_json('evaluation/results/2026-11-20-zap-test-api/patched/metrics/metrics.json'),
    'E2 patched': read_json('evaluation/results/2026-11-20-zap-vampi/patched/metrics/metrics.json'),
}
timing = [dict(run=int(r['run']), requests=int(r['requests']), ms=int(r['durationMs']))
          for r in csv.DictReader((RES / '2026-11-21-scanner-test-api' / 'rq3-timing.csv').open())]
per_case = list(csv.DictReader((RES / '2026-11-21-scanner-test-api' / 'comparison' / 'per-case.csv').open()))
seed = json.loads(run_node(['test-api/seeds/seed.js', '--json']))
ops = json.loads(run_node(['--input-type=module', '-e',
                           "import { loadSpec, listOperations } from './cli-tool/src/parser/openapi.js';"
                           "const o = listOperations(loadSpec('test-api/openapi.yaml'));"
                           "console.log(JSON.stringify({ total: o.length, auth: o.filter(x => x.requiresAuth).length,"
                           " owner: o.filter(x => x.accessControl?.ownership === 'owner').length }));"]))
FLAWS = json.loads(run_node(['--input-type=module', '-e',
                             "import { FLAWS } from './test-api/src/flaws.js'; console.log(JSON.stringify(FLAWS));"]))


def res(report, name):
    return next(r for r in report['results'] if r['name'] == name)


def m(report, name, scope='OVERALL'):
    return res(report, name)['metrics']['confirmed'][scope]


def f3(v):
    return 'n/a' if v is None else f'{v:.3f}'


RA, SO, ZAP = 'Role-aware', 'Status-only', 'OWASP ZAP'
b_ra, b_so, b_zap = m(bench, RA), m(bench, SO), m(bench, ZAP)
bp_ra, bp_so, bp_zap = m(bench, RA, 'PRIMARY'), m(bench, SO, 'PRIMARY'), m(bench, ZAP, 'PRIMARY')
bs_so = m(bench, SO, 'SECONDARY')
v_ra, v_so, v_zap = m(vampi, RA), m(vampi, SO), m(vampi, ZAP)
so_fp_scored = sum(1 for c in per_case if c['vulnerable'] == 'false' and c[SO] != 'not reported')
so_fp_unlisted = b_so['fp'] - so_fp_scored
so_alt_precision = b_so['tp'] / (b_so['tp'] + so_fp_scored)
durations = [t['ms'] for t in timing]
t_mean = sum(durations) / len(durations)
t_sd = (sum((d - t_mean) ** 2 for d in durations) / len(durations)) ** 0.5
REQ = timing[0]['requests']
GTT = gt['totals']
VGT = vgt['totals']
TN_PATTERNS = [c for c in gt['cases'] if not c['vulnerable'] and c.get('notes', '').startswith('True-negative pattern')]
assert len(set(t['requests'] for t in timing)) == 1
assert res(bench, RA)['requests'] == res(bench, SO)['requests'] == REQ


# ========================================================================================= citations
# key: (authors as in the reference list, year, verified-in-bib)
REFS = {
    'arcuri2019': (['Arcuri'], '2019', True),
    'atlidakis2019': (['Atlidakis', 'Godefroid', 'Polishchuk'], '2019', True),
    'atlidakis2020': (['Atlidakis', 'Godefroid', 'Polishchuk'], '2020', True),
    'barabanov2022': (['Barabanov', 'Dergunov', 'Makrushin', 'Teplov'], '2022', True),
    'bau2010': (['Bau', 'Bursztein', 'Gupta', 'Mitchell'], '2010', True),
    'corradini2022': (['Corradini', 'Zampieri', 'Pasqua', 'Viglianisi', 'Dallago', 'Ceccato'], '2022', True),
    'doupe2010': (['Doupé', 'Cova', 'Vigna'], '2010', True),
    'golmohammadi2023': (['Golmohammadi', 'Zhang', 'Arcuri'], '2023', True),
    'hevner2004': (['Hevner', 'March', 'Park', 'Ram'], '2004', True),
    'kim2022': (['Kim', 'Xin', 'Sinha', 'Orso'], '2022', True),
    'peffers2007': (['Peffers', 'Tuunanen', 'Rothenberger', 'Chatterjee'], '2007', True),
    'rfc7519': (['Jones', 'Bradley', 'Sakimura'], '2015', True),
    'rfc8725': (['Sheffer', 'Hardt', 'Jones'], '2020', True),
    'sandhu1996': (['Sandhu', 'Coyne', 'Feinstein', 'Youman'], '1996', True),
    'viglianisi2020': (['Viglianisi', 'Dallago', 'Ceccato'], '2020', True),
    'fielding2000': (['Fielding'], '2000', False),
    'owasp2023': (['OWASP Foundation'], '2023', False),
    'zap': (['ZAP Development Team'], 'n.d.', False),
    'vampi': (['erev0s'], 'n.d.', False),
    'crapi': (['OWASP Foundation'], 'n.d.', False),
}
_cited = []


def _names(key, narrative):
    authors, year, _ = REFS[key]
    first = key not in _cited
    if key not in _cited:
        _cited.append(key)
    joiner = ' and ' if narrative else ' & '
    if len(authors) == 1:
        n = authors[0]
    elif len(authors) == 2:
        n = joiner.join(authors)
    elif len(authors) <= 5 and first:  # Savonia: 3-5 authors -> all names on first citation
        n = ', '.join(authors[:-1]) + joiner + authors[-1]
    else:
        n = authors[0] + ' et al.'
    return n, year


def cite(text):
    """Resolves (@key; @key2) -> (Name & Name 2019; Name et al. 2020) and @@key -> Name et al. (2019)."""
    def paren(mo):
        parts = []
        for k in re.findall(r'@([\w]+)', mo.group(1)):
            n, y = _names(k, False)
            parts.append(f'{n} {y}')
        return '(' + '; '.join(parts) + ')'
    text = re.sub(r'\((@[\w]+(?:;\s*@[\w]+)*)\)', paren, text)

    def narr(mo):
        n, y = _names(mo.group(1), True)
        return f'{n} ({y})'
    return re.sub(r'@@([\w]+)', narr, text)


# ======================================================================================== document
doc = docx.Document(str(TEMPLATE))
body = doc.element.body
children = list(body.iterchildren())
STYLE = {s.name: s for s in doc.styles}


def para_obj(el):
    return docx.text.paragraph.Paragraph(el, doc._body)


def set_runs(p, text):
    """Keeps the first run's formatting, replaces the paragraph text."""
    runs = p.runs
    if not runs:
        p.add_run(text)
        return
    runs[0].text = text
    for r in runs[1:]:
        r._r.getparent().remove(r._r)


# ---- cover page
for tb in children[3].iter(qn('w:txbxContent')):  # report-type text box (Word + VML fallback)
    ps = list(tb.iter(qn('w:p')))
    for p_el, text in zip(ps, ['THESIS - BACHELOR\'S DEGREE', FIELD_OF_STUDY]):
        ts = list(p_el.iter(qn('w:t')))
        if ts:
            ts[0].text = text
            for t in ts[1:]:
                t.text = ''
set_runs(para_obj(children[8]), TITLE + ':')
set_runs(para_obj(children[9]), SUBTITLE)
p23 = para_obj(children[23])
p23.runs[2].text = AUTHOR
for r in p23.runs[3:]:
    r.text = ''
set_runs(para_obj(children[24]), '')
p25 = para_obj(children[25])  # keeps its page break
for r in p25.runs:
    if r._r.find(qn('w:br')) is None:
        r.text = ''
note = para_obj(children[12])
nr = note.add_run(DRAFT_NOTE)
nr.bold = True
nr.font.size = Pt(10)
nr.font.color.rgb = RGBColor(0xB1, 0x2F, 0x2F)
for el in children[17:22]:  # make room for the note so the cover stays on one page
    body.remove(el)
body.remove(children[28])  # empty paragraph after the abstract form; the page break (29) and section break (30) stay

# ---- abstract form
form = doc.tables[0]


def set_dropdown(cell, value):
    sdt = cell._tc.find(qn('w:sdt'))
    ts = list(sdt.find(qn('w:sdtContent')).iter(qn('w:t')))
    ts[0].text = value
    for t in ts[1:]:
        t.text = ''


def set_formtext(cell, value):
    """Sets the displayed result of the FORMTEXT field(s) in a cell (first field only)."""
    state, first = None, True
    for r in cell._tc.iter(qn('w:r')):
        fc = r.find(qn('w:fldChar'))
        if fc is not None:
            kind = fc.get(qn('w:fldCharType'))
            if kind == 'separate' and state is None:
                state = 'result'
            elif kind == 'end' and state == 'result':
                return
            continue
        if state == 'result':
            t = r.find(qn('w:t'))
            if t is not None:
                t.text = value if first else ''
                t.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
                first = False


set_dropdown(form.rows[0].cells[0], FIELD_OF_STUDY)
set_dropdown(form.rows[2].cells[0], DEGREE_PROGRAMME)
set_formtext(form.rows[4].cells[0], AUTHOR)
set_formtext(form.rows[6].cells[0], f'{TITLE}: {SUBTITLE}')
set_formtext(form.rows[7].cells[1], '[Date of approval, e.g. April 2027]')
PAGES_CELL = form.rows[7].cells[3]
set_formtext(form.rows[9].cells[0], 'None (self-initiated topic)')
set_formtext(form.rows[11].cells[0], 'broken access control, BOLA, BFLA, REST API, OpenAPI, security testing, '
                                     'authorization, OWASP API Security Top 10, design science research, CI/CD')

ABSTRACT = [
    'In the OWASP API Security Top 10 (2023), Broken Object Level Authorization (BOLA) is ranked first and Broken '
    'Function Level Authorization (BFLA) fifth. Both are hard for general-purpose scanners to find, because a wrongly '
    'granted request usually returns an ordinary success response; only knowing who owns an object and which role may '
    'use a function reveals the flaw.',
    'The aim of this thesis was to design, implement and evaluate a JavaScript tool that detects BOLA and BFLA '
    'automatically, following the Design Science Research methodology. The tool reads an OpenAPI specification and '
    'several user accounts, sends cross-user and cross-role requests, and decides with an ownership-differential '
    'oracle, using owner identifiers, the owner\'s own response and state verification after writes, whether access '
    'was wrongly granted. It was evaluated on a purpose-built benchmark API with 20 injected flaws, deliberate '
    'true-negative patterns and a fixed ground truth, and on the public vulnerable API VAmPI.',
    f'On the benchmark, the tool detected all {b_ra["tp"]} vulnerable cases with no false positives. A status-code-only '
    f'oracle using the same {REQ} requests reached the same recall with precision {f3(b_so["precision"])}, and OWASP '
    f'ZAP detected none of the flaws. On VAmPI the tool kept precision {f3(v_ra["precision"])} at recall '
    f'{f3(v_ra["recall"])}, missing one write whose effect the API does not expose. A scan took about '
    f'{t_mean / 1000:.1f} seconds, which suits CI use. The results are limited by an author-designed benchmark, policy '
    'annotations that real APIs often lack and a small number of cases.',
]
cell = form.rows[10].cells[0]
cps = cell.paragraphs
for p_obj, text in zip(cps, ABSTRACT[:2]):
    set_runs(p_obj, text)
    p_obj.style = STYLE['No Spacing']
for text in ABSTRACT[2:]:
    np_ = cell.add_paragraph(text, style=STYLE['No Spacing'])
for p_obj in cell.paragraphs[:-1]:
    p_obj.paragraph_format.space_after = Pt(6)

# ---- remove the template's sample content (TOC entries onwards), keep 'CONTENTS' heading and final sectPr
CONTENTS_IDX = next(i for i, el in enumerate(children) if ''.join(t.text or '' for t in el.iter(qn('w:t'))).strip() == 'CONTENTS')
LOF_HEADING = copy.deepcopy(next(el for el in children if ''.join(t.text or '' for t in el.iter(qn('w:t'))).strip() == 'LIST OF FIGURES'))
for el in children[CONTENTS_IDX + 1:]:
    if el.tag != qn('w:sectPr'):
        body.remove(el)


# ============================================================================================ fields
def _fld_run(kind):
    r = OxmlElement('w:r')
    fc = OxmlElement('w:fldChar')
    fc.set(qn('w:fldCharType'), kind)
    if kind == 'begin':
        fc.set(qn('w:dirty'), 'true')
    r.append(fc)
    return r


def _instr_run(instr):
    r = OxmlElement('w:r')
    it = OxmlElement('w:instrText')
    it.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
    it.text = f' {instr} '
    r.append(it)
    return r


def add_inline_field(p, instr, result):
    p._p.append(_fld_run('begin'))
    p._p.append(_instr_run(instr))
    p._p.append(_fld_run('separate'))
    p.add_run(result)
    p._p.append(_fld_run('end'))


def add_block_field(instr, entries, placeholder):
    """A multi-paragraph field (TOC / list of figures / tables). entries: [(style, text)]."""
    entries = entries or [('Normal', placeholder)]
    paras = []
    for style, text in entries:
        p = doc.add_paragraph(style=STYLE[style] if style in STYLE else None)
        paras.append((p, text))
    first, last = paras[0][0], paras[-1][0]
    first._p.append(_fld_run('begin'))
    first._p.append(_instr_run(instr))
    first._p.append(_fld_run('separate'))
    for p, text in paras:
        for i, part in enumerate(text.split('\t')):
            if i:
                p.add_run().add_tab()
            p.add_run(part)
    last._p.append(_fld_run('end'))


def heading_other(text):
    el = copy.deepcopy(LOF_HEADING)
    body.insert(len(body) - 1, el)
    p = para_obj(el)
    set_runs(p, text)
    return p


def page_break():
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


# ===================================================================================== content model
# Content is collected as operations first, so table and figure numbers can be referenced anywhere
# in the text as {tab:key} / {fig:key} before the object itself appears.
OPS = []
TAB_NO, FIG_NO = {}, {}


def H(text, level=1):
    OPS.append(('h', text, level))


def P(*texts):
    for t in texts:
        OPS.append(('p', t))


def T(key, caption, header, rows, widths, note=None):
    TAB_NO[key] = len(TAB_NO) + 1
    OPS.append(('t', key, caption, header, rows, widths, note))


def F(key, image, caption, width_cm=15.0):
    FIG_NO[key] = len(FIG_NO) + 1
    OPS.append(('f', key, image, caption, width_cm))


def RAW(fn):
    OPS.append(('raw', fn))


CAT_LABEL = {
    'BOLA': 'Broken Object Level Authorization', 'BFLA': 'Broken Function Level Authorization',
    'AUTH_MISSING': 'Missing authentication', 'AUTH_INVALID_TOKEN': 'Malformed token accepted',
    'JWT_SIGNATURE': 'JWT signature not verified', 'JWT_NONE_ALG': 'Unsigned JWT (alg: none) accepted',
    'JWT_EXPIRED': 'Expired JWT accepted',
}
SCOPE_LABEL = {'PRIMARY': 'BOLA + BFLA', 'BOLA': 'BOLA', 'BFLA': 'BFLA', 'SECONDARY': 'Authentication / JWT',
               'OVERALL': 'All categories'}

# ============================================================================== 1 INTRODUCTION
H('Introduction')
P(cite('Modern web and mobile applications, cloud services and Internet of Things (IoT) platforms are built around '
       'application programming interfaces (APIs). Most of these APIs follow the REST architectural style and exchange '
       'JSON documents over HTTP (@fielding2000). Because an API exposes the data and functions of an application '
       'directly to any client that can send HTTP requests, the server must decide for every request whether the '
       'caller is allowed to perform it. When this decision is missing or wrong, an attacker does not need any '
       'sophisticated technique: changing an identifier in a URL or calling a function that the user interface '
       'never shows can be enough to read or change other users\' data.'),
  cite('The OWASP API Security Top 10 (@owasp2023) ranks Broken Object Level Authorization (BOLA) as the most '
       'important API security risk and Broken Function Level Authorization (BFLA) as the fifth. BOLA means that the '
       'API checks that the caller is logged in, but not whether the addressed object belongs to the caller. BFLA '
       'means that a function intended for one role, for example an administrator, can also be called by another '
       'role. Both flaws are logic flaws in the authorization layer of the application, not errors in input handling.'),
  cite('Such flaws are hard to find automatically. A general-purpose dynamic application security testing (DAST) '
       'tool, such as OWASP ZAP (@zap), sends requests and inspects the responses for signs of known vulnerability '
       'classes. A successful BOLA attack, however, typically returns an ordinary 200 OK response with well-formed '
       'data. Only a tester who knows that the returned object belongs to another user, or that the calling role '
       'should not have access to the function, can recognise the response as a vulnerability. Evaluations of '
       'black-box scanners have long reported that vulnerability classes which depend on application state and '
       'logic are where these tools are weakest (@doupe2010; @bau2010).'),
  'The same problem is relevant in IoT platforms, where REST APIs are used to register devices and to read and write '
  'sensor data. If any authenticated user can read the readings of any device, or inject readings into it, the '
  'confidentiality and integrity of the whole platform are at risk. The benchmark built in this thesis therefore '
  'includes IoT devices and sensor readings next to typical business resources such as orders and invoices.')
H('Aim and research questions', 2)
P('The aim of this thesis is to design, implement and evaluate a JavaScript-based tool that automatically detects '
  'broken access control vulnerabilities, in particular BOLA and BFLA, in REST APIs. The tool reads an OpenAPI '
  'specification and the credentials of several test accounts with different roles, sends the same requests as '
  'different users and roles, and compares the responses to decide where one user can access another user\'s data '
  'or functions. The work is guided by three research questions, which are taken unchanged from the approved topic '
  'proposal:',
  'RQ1: How can a role-aware testing tool use an OpenAPI specification and several user accounts to detect BOLA and '
  'BFLA vulnerabilities automatically?',
  'RQ2: How do its precision, recall, and false-positive rate compare with OWASP ZAP and with a simpler approach that '
  'checks only HTTP status codes?',
  'RQ3: How much time and how many requests does the tool need, and can it run as part of a CI pipeline?')
H('Research approach', 2)
P(cite('The thesis is research-oriented development work that follows Design Science Research (DSR) '
       '(@hevner2004; @peffers2007). In DSR, knowledge is produced by building an artifact that addresses a '
       'relevant problem and by evaluating the artifact rigorously. Here the artifact is the role-aware testing tool. '
       'It is evaluated in controlled experiments on a benchmark API with a known ground truth and on VAmPI, an '
       'intentionally vulnerable public API (@vampi). The tool is compared with OWASP ZAP and with a status-code-only '
       'variant of itself, using precision, recall, F1 score, false-positive rate, execution time and number of '
       'requests. All testing was done locally in Docker containers against intentionally vulnerable software; no '
       'third-party systems were tested and no personal data was used.'))
H('Structure of the thesis', 2)
P('Chapter 2 presents the theoretical background: REST APIs and OpenAPI, authentication and authorization, BOLA and '
  'BFLA, JSON Web Tokens and existing approaches to automated API security testing, and identifies the research gap. '
  'Chapter 3 states the purpose, objectives and research questions. Chapter 4 describes the methodology and the '
  'implementation: the DSR process, the benchmark API and its ground truth, the design of the tool and the evaluation '
  'design. Chapter 5 reports the results of the executed experiments and states clearly which planned experiments '
  'were not executed. Chapter 6 answers the research questions, discusses limitations and threats to validity and '
  'evaluates the use of artificial intelligence in the work. Chapter 7 concludes the thesis and proposes future work.')

# ============================================================================== 2 THEORY
H('Theoretical background')
P('This chapter introduces the concepts on which the tool is built and reviews existing approaches to automated '
  'testing of REST APIs. It ends with the research gap that motivates the thesis.')
H('REST APIs and the OpenAPI Specification', 2)
P(cite('Representational State Transfer (REST) is an architectural style for distributed hypermedia systems that '
       'was described by @@fielding2000. A REST API exposes resources, such as users, orders or devices, under '
       'uniform resource identifiers, and clients manipulate them with the standard HTTP methods: GET reads a '
       'resource, POST creates one, PUT and PATCH change one, and DELETE removes one. The server is stateless with '
       'respect to the client session, so every request carries the information needed to process it, including the '
       'credentials of the caller. Resources are commonly addressed by identifiers in the path, for example '
       '/api/orders/{orderId}, and this is exactly where object-level authorization must be enforced.'),
  'The OpenAPI Specification is a machine-readable format, written in YAML or JSON, that describes the operations '
  'of an HTTP API: the paths and methods, path and query parameters, request and response bodies with their JSON '
  'schemas, and the security schemes that apply to each operation. Because the description is machine-readable, it '
  'can be used to generate documentation, client code and tests. For security testing, an OpenAPI document gives a '
  'tool the complete inventory of operations and enough schema information to construct valid requests. It does not, '
  'however, describe which user owns which object, or which role may call which operation. OpenAPI allows vendor '
  'extensions (fields beginning with x-), and this thesis uses such an extension, x-access-control, to record the '
  'intended access policy of the benchmark API. Real APIs rarely contain this information, which is discussed as a '
  'limitation in Chapter 6.')
H('Authentication, authorization and role-based access control', 2)
P('Authentication establishes who the caller is, for example by checking a password and issuing a token. '
  'Authorization decides what the authenticated caller may do. Broken access control is a failure of authorization: '
  'the caller is correctly identified, but the server allows an operation that the policy forbids. The distinction '
  'matters for testing, because a tool that only checks whether unauthenticated requests are rejected will not find '
  'authorization flaws that affect logged-in users.',
  cite('Role-based access control (RBAC) assigns permissions to roles and roles to users (@sandhu1996). An '
       'administrator role may manage user accounts, a regular user role may create and manage its own objects, and a '
       'read-only guest role may only read. RBAC alone does not express object ownership: two users with the same '
       'role must still be prevented from accessing each other\'s objects. Typical API policies therefore combine a '
       'role rule (which roles may call an operation) with an ownership rule (which objects a caller may address). '
       'The benchmark in this thesis uses exactly this combination, and the tool tests both parts: cross-role tests '
       'for the role rule and cross-user tests for the ownership rule.'))
H('Broken object level and broken function level authorization', 2)
P(cite('BOLA (API1:2023) occurs when an API uses an identifier supplied by the client to access an object without '
       'checking that the caller is allowed to access that particular object (@owasp2023). A typical example is '
       'GET /api/orders/18, where the API returns order 18 to any authenticated user although it belongs to another '
       'customer. BOLA also affects write and delete operations: a user may change or delete another user\'s object. '
       'Because the identifier is usually a simple number or string, an attacker can enumerate identifiers with '
       'little effort.'),
  cite('BFLA (API5:2023) occurs when the API does not check whether the caller\'s role may use a function '
       '(@owasp2023). Administrative functions such as listing all users, deleting accounts or triggering backups '
       'are common targets. The function is often hidden from the user interface but still reachable through the '
       'API, so the absence of a button is mistaken for access control.'),
  'For automated detection, the two flaws share an important property: the vulnerable response is usually a normal '
  'success response. The difference between a vulnerability and correct behaviour lies in the relationship between '
  'the caller, the object and the policy, not in the HTTP status code. At the same time, a success status does not '
  'prove a vulnerability. Public objects may be readable by everybody by design; an API may ignore the identifier '
  'in the path and return the caller\'s own data; it may answer 200 with a body such as {"success": false} '
  '(a soft denial); it may accept a request asynchronously with 202 Accepted and then not apply it; or it may return '
  'a filtered view that contains only the caller\'s own data. These correct behaviours are called true-negative '
  'patterns in this thesis. A detector that treats every 2xx response to a forbidden request as a vulnerability '
  'reports all of them as false positives.')
H('JSON Web Tokens', 2)
P(cite('Many REST APIs authenticate requests with bearer tokens in the Authorization header, often in the form of '
       'JSON Web Tokens (JWT). A JWT consists of a header, a payload of claims such as the subject (sub) and the expiry '
       'time (exp), and a signature (@rfc7519). The server must verify the signature with the expected algorithm and '
       'key and must reject expired tokens. The JWT Best Current Practices document @@rfc8725 describes typical '
       'implementation mistakes, among them accepting tokens whose header declares the algorithm "none" and therefore '
       'carry no signature at all.'),
  'Token handling errors are authentication flaws rather than authorization flaws, but they lead to the same '
  'outcome: a caller obtains access that the policy does not grant. The tool therefore tests five authentication '
  'and token cases as secondary checks: a missing token, a malformed token, a token with an invalid signature, an '
  'unsigned token with alg: none, and an expired token. In the evaluation they are reported separately from BOLA and '
  'BFLA, so that the many easy authentication test cases do not dominate the results for the main research focus.')
H('Automated security testing of REST APIs and its blind spots', 2)
P(cite('Automated testing of REST APIs is an active research area. @@golmohammadi2023 survey the field and show that '
       'most approaches generate test cases from an OpenAPI description, using random, search-based or model-based '
       'techniques, and use mainly server errors and schema violations as test oracles. EvoMaster generates test '
       'cases with search-based techniques (@arcuri2019), RESTler performs stateful fuzzing by inferring dependencies '
       'between requests (@atlidakis2019), and RestTestGen and its successor generate nominal and error scenarios from '
       'the specification (@viglianisi2020; @corradini2022). An empirical comparison of such tools by @@kim2022 found '
       'that they still leave a large part of API behaviour untested.'),
  cite('Most of these tools are designed to find functional faults and crashes, and their oracles do not encode who '
       'may access what. A notable exception is the work of @@atlidakis2020, who added security checkers to stateful '
       'REST API fuzzing, including checks related to whether resources created by one user can be accessed by '
       'another. @@barabanov2022 proposed detecting access control vulnerabilities by processing the API specification, '
       'which is the closest related work to this thesis. [Author: read both papers and describe precisely how their '
       'detection and evaluation differ from this thesis.]'),
  cite('General-purpose DAST tools such as OWASP ZAP (@zap) can import an OpenAPI definition and scan every operation. '
       'Their active scan rules, however, look for injection, misconfiguration and information disclosure, and they '
       'normally run as a single user. Without a second user and knowledge of ownership, a scanner has no way to tell '
       'that a successful response exposes someone else\'s data. Earlier evaluations of black-box web scanners '
       'reached the same conclusion for web applications in general: vulnerability classes that depend on '
       'application logic and state are the most frequently missed (@doupe2010; @bau2010). Manual tools exist for '
       'this purpose, for example the Autorize and AuthMatrix extensions of Burp Suite, which repeat requests with the '
       'session of another user. They support a human tester but require manual configuration and interpretation and '
       'are not designed for unattended use in a pipeline. [Author: add sources for Autorize and AuthMatrix if they '
       'are discussed.]'))
H('Research gap', 2)
P('The review shows three gaps. First, automated REST API testing tools rarely use more than one identity and rarely '
  'have an oracle for authorization, so BOLA and BFLA are largely outside their scope. Second, the simplest way to '
  'add such an oracle, flagging any successful response to a forbidden request, is known to be imprecise, but the '
  'size of this imprecision is rarely measured against a ground truth that contains legitimate success responses. '
  'Third, comparisons are often made on applications whose vulnerabilities are not fully known, which makes '
  'false-positive rates hard to measure. This thesis addresses these gaps by building a tool that uses several '
  'accounts and an ownership-aware oracle, by comparing that oracle with a status-only oracle on exactly the same '
  'requests, and by evaluating both on a benchmark whose ground truth, including deliberate true-negative patterns, '
  'is fixed in advance.')

# ============================================================================== 3 PURPOSE
H('Purpose, objective and research questions')
P('The purpose of the thesis is to help developers find broken access control vulnerabilities in REST APIs early, '
  'automatically and with few false alarms, so that such checks can be part of everyday development rather than an '
  'occasional manual penetration test.',
  'The objective is to produce and evaluate an artifact: a command-line tool written in JavaScript (Node.js) that '
  'reads an OpenAPI specification and a configuration with several test accounts and roles, generates cross-user and '
  'cross-role test requests, and decides from the response content and object ownership, not only from the HTTP '
  'status code, whether access was wrongly granted. The tool produces findings with evidence in JSON and HTML reports '
  'and can gate a continuous integration (CI) pipeline through its exit code. A second objective is a reusable '
  'evaluation environment: a benchmark API with known flaws and a fixed ground truth, and an evaluation pipeline '
  'that scores any tool against it.',
  'The research questions, as approved in the topic proposal, are:',
  'RQ1: How can a role-aware testing tool use an OpenAPI specification and several user accounts to detect BOLA and '
  'BFLA vulnerabilities automatically?',
  'RQ2: How do its precision, recall, and false-positive rate compare with OWASP ZAP and with a simpler approach that '
  'checks only HTTP status codes?',
  'RQ3: How much time and how many requests does the tool need, and can it run as part of a CI pipeline?',
  'RQ1 is a design question and is answered by the construction of the tool and by its demonstration on two APIs. '
  'RQ2 is an evaluation question and is answered with the metrics defined in Section 4.5. RQ3 concerns the practical '
  'cost and the integration of the tool into a development workflow.',
  'The scope is limited to BOLA and BFLA as primary targets and to five authentication and token checks as secondary '
  'targets. Other API risks, such as broken object property level authorization (mass assignment), injection or '
  'rate limiting, are outside the scope. The thesis is self-initiated and has no commissioning organisation.')

# ============================================================================== 4 METHOD
H('Methodology and implementation')
H('Design Science Research', 2)
P(cite('Design Science Research creates and evaluates artifacts, such as constructs, models, methods and '
       'instantiations, that solve identified organisational or technical problems (@hevner2004). @@peffers2007 '
       'describe the process as six activities: problem identification and motivation, definition of the objectives '
       'of a solution, design and development, demonstration, evaluation, and communication. Table {tab:dsr} shows how '
       'these activities were carried out in this thesis. DSR fits the topic because the research questions ask both '
       'how such a tool can be built (RQ1) and how well it works compared with alternatives (RQ2 and RQ3).'),
  'The evaluation follows the logic of a controlled experiment. The independent variable is the detection approach; '
  'the dependent variables are the detection metrics and the cost of a run. The benchmark and its ground truth were '
  'designed and fixed before the tool was run, and the configuration of OWASP ZAP and the mapping of its alerts were '
  'fixed before ZAP was run. Section 6.5 discusses where this order could not fully protect the evaluation from '
  'bias.')
T('dsr', 'Design Science Research activities and their realisation in this thesis',
  ['DSR activity (Peffers et al. 2007)', 'Realisation in this thesis', 'Evidence in the repository'],
  [['1 Problem identification and motivation', 'BOLA and BFLA are hard to detect for scanners that do not know object ownership or role policy', 'Topic proposal; Chapter 2'],
   ['2 Objectives of a solution', 'Detect BOLA/BFLA from an OpenAPI specification and several accounts, with few false positives, fast enough for CI', 'Research questions RQ1-RQ3'],
   ['3 Design and development', 'Benchmark API, role-aware testing tool, reporting, CI workflow', 'test-api/, cli-tool/, .github/workflows/'],
   ['4 Demonstration', 'Runs against the benchmark and VAmPI in Docker', 'docker-compose.yml, evaluation/results/'],
   ['5 Evaluation', 'Precision, recall, F1, FPR, time and requests against a ground truth; comparison with OWASP ZAP and a status-only baseline', 'evaluation/, ground-truth manifests'],
   ['6 Communication', 'Thesis report, results dashboard and public repository', 'README.md, docs/']],
  [4.3, 7.2, 4.5])

H('Benchmark API', 2)
P(f'Existing intentionally vulnerable APIs do not provide a complete, machine-readable list of their vulnerabilities, '
  f'and they contain few legitimate success responses to forbidden requests. To measure false positives as well as '
  f'detections, a dedicated benchmark API was built with Node.js and Express. It models a small business and IoT '
  f'platform with user profiles, orders, invoices nested under orders, private and public documents, IoT devices '
  f'with sensor readings, a product catalogue and administrative functions. Its OpenAPI specification describes '
  f'{ops["total"]} operations, of which {ops["auth"]} require authentication and {ops["owner"]} have an owner-only '
  f'object policy. Table {{tab:roles}} lists the roles, and Table {{tab:size}} summarises the size of the benchmark.',
  'Every operation in the specification carries an x-access-control extension that records the intended policy: '
  'the roles that may call it, whether access is restricted to the owner of the addressed object, and the name of '
  'the field that holds the owner\'s identifier. The implementation deliberately deviates from this policy on a known '
  'set of operations. The specification therefore states what should happen, and the code determines what actually '
  'happens.')
T('roles', 'Roles of the benchmark API', ['Role', 'Intended permissions'],
  [['admin', 'All functions, including administrative functions; may access every object'],
   ['user', 'Regular customer: creates and manages own objects; no administrative functions'],
   ['guest', 'Authenticated, read-only: may not create objects; no administrative functions'],
   ['(anonymous)', 'Only public operations (health check, login, product catalogue)']],
  [3.0, 13.0])
s = seed['summary']
T('size', 'Size of the benchmark API', ['Item', 'Count'],
  [['OpenAPI operations', ops['total']], ['Operations requiring authentication', ops['auth']],
   ['Operations with an owner-only object policy', ops['owner']],
   ['Synthetic accounts (admin / user / guest)', f"{len(seed['accounts'])} ({sum(a['role'] == 'admin' for a in seed['accounts'])} / {sum(a['role'] == 'user' for a in seed['accounts'])} / {sum(a['role'] == 'guest' for a in seed['accounts'])})"],
   ['Injected flaws (one per vulnerable ground-truth case)', len(FLAWS)],
   ['Seeded orders / invoices / documents / IoT devices', f"{s['orders']} / {s['invoices']} / {s['documents']} / {s['devices']}"]],
  [11.0, 5.0])
P(f'Twenty flaws were injected: {gt["summary"]["BOLA"]["vulnerable"]} BOLA, {gt["summary"]["BFLA"]["vulnerable"]} BFLA, '
  f'two missing-authentication flaws, one endpoint that accepts any bearer value, one that does not verify the JWT '
  f'signature, one that accepts unsigned tokens and one that ignores the expiry time (Table {{tab:flaws}}). The flaws '
  'cover read, write and delete operations, objects with and without an owner identifier in the response, and '
  'nested resources. Each flaw is guarded by one identifier in a flaw registry, so the environment variable '
  'FLAWS=all starts the vulnerable build and FLAWS=none starts a patched build of the same code in which every flaw '
  'is replaced by its correct implementation. The patched build serves as a second, independent true-negative '
  'dataset and as the build that a CI gate should let through.')
T('flaws', 'Injected flaws in the vulnerable build of the benchmark API',
  ['Category', 'Operation', 'Kind', 'Flaw ID'],
  [[c['category'], f"{c['method']} {c['path']}", c.get('kind', ''), c['flawId']] for c in gt['cases'] if c['vulnerable']],
  [3.0, 6.0, 1.4, 5.6], note='Source: test-api/src/flaws.js and test-api/ground-truth.json.')
P(f'Next to the flaws, {len(TN_PATTERNS)} correctly protected operations were designed to answer with a 2xx status '
  f'to a request that the policy forbids (Table {{tab:tn}}). They implement the true-negative patterns described in '
  'Section 2.3: public documents that are readable by design, an endpoint that ignores the identifier in the path and '
  'returns the caller\'s own data, two soft denials, a 202 Accepted that is not applied for non-owners, and a '
  'role-filtered administrative view. These cases make the benchmark able to distinguish an oracle that inspects '
  'content and ownership from one that inspects only status codes.')
T('tn', 'Correctly protected operations that still answer with a 2xx status (true-negative patterns)',
  ['Operation', 'Category', 'Correct behaviour'],
  [[f"{c['method']} {c['path']}", c['category'], c['notes'].replace('True-negative pattern. ', '')] for c in TN_PATTERNS],
  [5.6, 1.8, 8.6])

H('Ground truth and counting rules', 2)
P(f'The unit of analysis is a case: one combination of HTTP method, OpenAPI path template and vulnerability '
  f'category, labelled vulnerable or secure. The ground truth is generated by a script from a hand-labelled list of '
  f'the {GTT["vulnerable"]} vulnerable cases and from documented applicability rules, and automated tests fail if the '
  f'committed ground truth drifts from the specification or the flaw registry. For the vulnerable build it contains '
  f'{GTT["cases"]} cases, of which {GTT["scored"]} are scored and {GTT["excluded"]} are excluded by the root-cause '
  f'rule explained below. Table {{tab:gt}} summarises the four labelled datasets, and Table {{tab:rules}} lists the '
  'counting rules.',
  'The root-cause rule addresses an overlap between the authentication categories. An endpoint that requires no '
  'authentication at all trivially also "accepts" a malformed, unsigned or expired token. Counting all of these '
  'would score one root cause several times. Where a broader authentication flaw exists on an operation, the narrower '
  'categories on the same operation are therefore excluded from scoring. A consequence that becomes important in '
  'Chapter 5 is that a finding which matches no scored case, including a finding on an excluded case, is counted '
  'as a false positive.')
cats = list(CAT_LABEL)
cnt = lambda g: {k: f"{v['vulnerable']} / {v['secure']}" for k, v in g['summary'].items()}
cols = [cnt(gt), cnt(gt_sec), cnt(vgt), cnt(vgt_sec)]
gt_rows = [[CAT_LABEL[k], *[c.get(k, '-') for c in cols]] for k in cats]
gt_rows.append(['Scored cases (vulnerable)', *[f"{g['totals']['scored']} ({g['totals']['vulnerable']})" for g in (gt, gt_sec, vgt, vgt_sec)]])
T('gt', 'Ground truth: vulnerable / secure cases per category',
  ['Category', 'Benchmark, vulnerable build', 'Benchmark, patched build', 'VAmPI, vulnerable mode', 'VAmPI, patched mode'],
  gt_rows, [4.4, 2.9, 2.9, 2.9, 2.9],
  note='VAmPI\'s patched mode keeps one vulnerable case: an unauthenticated debug endpoint that VAmPI exposes in both modes.')
T('rules', 'Unit of analysis and counting rules', ['Rule', 'Definition'],
  [['Case', 'One (HTTP method, OpenAPI path template, category) with a known label: vulnerable or secure'],
   ['Detection', 'A tool detects a case when at least one of its findings has the same method, path template and category'],
   ['BOLA applicability', 'Operations whose intended policy restricts access to the owner of the addressed object'],
   ['BFLA applicability', 'Non-public operations whose intended roles exclude at least one role and that have no ownership rule'],
   ['Authentication applicability', 'Every operation that requires authentication, for each authentication/JWT category'],
   ['Root-cause rule', 'Where a broader authentication flaw exists on an operation, the narrower authentication categories on that operation are excluded from scoring'],
   ['Unlisted findings', 'A finding that matches no scored case counts as a false positive'],
   ['Independence', 'Labels are fixed from the benchmark design before any tool is run and are checked by automated consistency tests']],
  [4.0, 12.0])

H('Design of the role-aware testing tool', 2)
P('The tool is a Node.js command-line program without a test framework or heavy dependencies; at runtime it uses '
  'only a YAML parser besides the Node.js standard library. Figure {fig:arch} shows its architecture and the '
  'evaluation pipeline around it. The numbered steps are described below.')
F('arch', FIG / 'fig-architecture.png', 'Architecture of the role-aware testing tool and the evaluation pipeline', 14.5)
P('Inputs and policy (step 1). The OpenAPI parser resolves references, path and query parameters, request bodies '
  'and security requirements and produces an inventory of operations. The configuration file lists the target, the '
  'accounts with their roles and credentials, the response fields that carry owner identifiers, indicators of public '
  'objects, an allowlist of hosts the tool may contact, and limits such as a request timeout and a maximum number of '
  'requests per run. The intended policy of each operation is taken from the x-access-control extension when the '
  'specification has one; for APIs without annotations, such as VAmPI, access rules in the configuration supply the '
  'same information and override the specification. The tool refuses any target that is not on the allowlist.',
  'Login and identities (step 2). The tool logs in with every configured account, stores the bearer token and '
  'extracts the identity of the account, either from the login response or from the subject claim of the token. '
  'It then selects the actors for testing: an attacker and a victim with the same role for cross-user tests, an '
  'administrator as a reference, and a lower-privileged role such as a guest.',
  'Object discovery (step 3). To test object-level authorization, the tool needs identifiers of objects that belong '
  'to the victim. It reads the victim\'s collections through list endpoints and recognises ownership through the '
  'configured owner fields, including nested fields. For destructive tests it creates disposable objects as the '
  'victim instead of using seeded data, so that a DELETE test never removes data that other tests depend on.',
  'Shared test generation (step 4). From the inventory, the policy and the discovered objects, the test generator '
  'produces a deterministic test plan. For every owner-only operation with a path identifier it creates cross-user '
  'BOLA tests: the attacker, and the guest where the role rule allows it, addresses the victim\'s object. For every '
  'operation whose role rule excludes some configured role it creates cross-role BFLA tests with an account of each '
  'excluded role. For every operation that requires authentication it creates the five authentication and token '
  'probes; an expired token is forged only when a benchmark-only signing secret is supplied through an environment '
  'variable. The essential design decision is that test generation is separated from the decision about each test. '
  'The same plan, and therefore exactly the same HTTP requests, is evaluated by both oracles, so that differences '
  'between them can be attributed to the decision rule.',
  'Execution (step 5). Each test is executed with throttling and time-outs, and the HTTP client counts every request '
  'for RQ3. For BOLA tests on read operations, the tool also requests the same object as its owner to obtain a '
  'baseline response. For write and delete operations, it reads the object as its owner before and after the '
  'attacker\'s request, and write requests carry a unique probe marker so that a persisted change can be recognised.',
  'Ownership-differential oracle (step 6a). The oracle first treats any non-2xx response and any soft denial as '
  'denied. For BOLA it then ignores objects that match a configured public indicator, and on read operations it '
  'compares the owner identifiers in the response with the identities of the attacker and the victim: the victim\'s '
  'identifier is a confirmed vulnerability, while the attacker\'s own identifier means that the path identifier was '
  'ignored. If the response carries no owner identifier, it is compared with the owner\'s baseline response. On '
  'write and delete operations, the decision comes from the state verification: a probe marker or changed state in '
  'the owner\'s re-read, or a 404 after a delete, confirms a vulnerability; an unchanged state means the request was '
  'accepted but not applied. For BFLA, a role-filtered view that contains only the caller\'s own data is treated as '
  'denied. Every finding is classified as confirmed or potential, and only confirmed findings count at the strict '
  'threshold.',
  'Status-only oracle (step 6b). The baseline oracle inspects nothing except the status code: any 2xx response to a '
  'request that the policy forbids is reported as a confirmed vulnerability. It represents the simplest way to turn '
  'multi-account requests into findings.',
  'Root-cause filter. In role-aware mode, the engine applies the root-cause rule of Section 4.3 to its own output: '
  'when a broader authentication flaw is confirmed on an operation, narrower authentication findings on the same '
  'operation are not reported. In status-only mode this filter is not applied. This asymmetry affects only the '
  'authentication categories, and its effect on the results is quantified in Section 5.3.',
  'Output, reporting and CI (step 7). Both oracles write a findings document in a common JSON format that records '
  'for each finding the category, operation, attacker and victim, the expected and observed behaviour and redacted '
  'evidence, together with the number of requests and the duration of the run. A report command produces a redacted '
  'JSON report and a self-contained HTML report and returns exit code 1 when a confirmed finding at or above a chosen '
  'severity exists, which lets the tool gate a pipeline. A GitHub Actions workflow runs the unit and integration '
  'tests, starts both builds of the benchmark in Docker, runs the scan, gates the patched build and checks the '
  'vulnerable build for regressions against the ground truth.')

H('Evaluation design', 2)
P(cite('Three approaches are compared. The role-aware tool with the ownership-differential oracle is the artifact. '
       'The status-only oracle is a baseline that isolates the contribution of the decision rule, because it uses the '
       'same requests. OWASP ZAP version 2.17.0 (@zap) represents a widely used open-source DAST tool; it was run in '
       'its standard API scan mode (zap-api-scan) with the OpenAPI definition and one authenticated user, which is how '
       'a team would typically add it to a pipeline. ZAP\'s alerts were converted into the common findings format by '
       'an adapter whose mapping from CWE identifiers to categories was fixed before ZAP was run. ZAP\'s separate '
       'Access Control Testing add-on, which requires manually configured contexts for each user, was not used.'),
  cite('Two targets were used: the benchmark API (vulnerable and patched builds) and VAmPI (@vampi), a deliberately '
       'vulnerable REST API written in Python, in its vulnerable and patched modes. For VAmPI a ground truth of 35 '
       'cases was labelled from its source code, and its intended policy and ownership fields were supplied by '
       'configuration because its specification has no policy annotations. A third target, OWASP crAPI (@crapi), was '
       'planned and its setup documented, but it was not evaluated (Section 5.1).'),
  'Table {tab:metrics} defines the metrics. Precision, recall, F1 and the false-positive rate are computed per '
  'category, for the BOLA and BFLA categories together (the primary scope of RQ1 and RQ2), for the authentication '
  'and token categories together (the secondary scope), and over all categories. Grouping is needed because the '
  'benchmark contains about two hundred easy authentication true negatives, which would otherwise make every '
  'tool\'s overall false-positive rate look small. When a denominator is zero, the metric is reported as undefined '
  '(n/a) and never replaced by 0 or 1. Results are reported at a strict threshold (confirmed findings only) and a '
  'loose threshold (confirmed and potential findings); in all executed runs the two thresholds gave identical '
  'values, so only the strict threshold is shown. Raw counts of true and false positives and negatives are always '
  'reported next to the ratios, because the number of vulnerable cases is small.',
  'For RQ3, the role-aware scan of the benchmark was repeated five times, with the benchmark reset to its seed state '
  'between runs, and the number of requests and the wall-clock duration were recorded. Table {tab:exps} lists all '
  'planned experiments and Table {tab:env} the software environment.')
T('metrics', 'Evaluation metrics', ['Metric', 'Definition', 'Research question'],
  [['Precision', 'TP / (TP + FP)', 'RQ2'], ['Recall (detection rate)', 'TP / (TP + FN)', 'RQ2'],
   ['F1 score', '2 · Precision · Recall / (Precision + Recall)', 'RQ2'], ['False-positive rate (FPR)', 'FP / (FP + TN)', 'RQ2'],
   ['Execution time', 'Wall-clock duration of one run', 'RQ3'], ['Number of requests', 'HTTP requests sent during one run', 'RQ3'],
   ['CI suitability', 'Runs unattended in a CI pipeline; exit code gates the pipeline', 'RQ3']],
  [3.8, 9.2, 3.0], note='TP, FP, TN, FN = true positives, false positives, true negatives, false negatives (counted per case).')


def experiment_rows():
    rows, inside = [], False
    for line in (ROOT / 'evaluation' / 'README.md').read_text().splitlines():
        if line.startswith('| ID '):
            inside = True
            continue
        if inside:
            if not line.startswith('|'):
                break
            if set(line.replace('|', '').strip()) <= set('-: '):
                continue
            c = [re.sub(r'\*\*|`', '', x.strip()) for x in line.strip().strip('|').split('|')]
            rows.append([c[0], c[1], c[2].split(':')[0]])
    return rows


EXPS = experiment_rows()
T('exps', 'Planned and executed experiments', ['ID', 'Description', 'Status'], EXPS, [1.2, 10.3, 4.5],
  note='Status as recorded in evaluation/README.md. Only executed experiments have results.')
lock = read_json('package-lock.json')['packages']
T('env', 'Software used in the implementation and the experiments', ['Software', 'Version', 'Role'],
  [['Node.js', subprocess.run(['node', '--version'], capture_output=True, text=True).stdout.strip(), 'Runtime of the benchmark, the tool and the evaluation [author: confirm the version used for the experiments]'],
   ['Express', lock['node_modules/express']['version'], 'Web framework of the benchmark API'],
   ['jsonwebtoken', lock['node_modules/jsonwebtoken']['version'], 'Token issuing and verification in the benchmark API'],
   ['yaml', lock['node_modules/yaml']['version'], 'Reading OpenAPI and configuration files'],
   ['OWASP ZAP', zap_runs['E1 vulnerable'].get('@version', ''), 'Comparison tool (Docker image ghcr.io/zaproxy/zaproxy:stable)'],
   ['VAmPI', 'erev0s/vampi:latest (pulled 2026-11-20)', 'External benchmark application'],
   ['Docker, Docker Compose', 'see docker-compose.yml', 'Isolated local test environment'],
   ['GitHub Actions', 'workflow security-scan.yml', 'CI pipeline (implemented, not yet run on GitHub)']],
  [3.4, 4.2, 8.4])

H('Ethical considerations', 2)
P('All experiments were run on the local benchmark API and on intentionally vulnerable training applications in '
  'Docker containers bound to the local machine. The tool refuses targets outside its host allowlist, and the ZAP '
  'runner refuses non-local targets. All accounts and data are synthetic, no human participants were involved and '
  'no third-party system was tested. The tool generates attack traffic and must only be used against systems that '
  'the user is authorised to test.')

# ============================================================================== 5 RESULTS
H('Results')
H('Executed and not executed experiments', 2)
executed = [r[0] for r in EXPS if r[2].lower().startswith('executed')]
P(f'Of the eight planned experiments, {", ".join(executed[:-1])} and {executed[-1]} were executed in full on '
  '20-21 November 2026, and E7 was executed in part (Table {tab:exps}). E6, an ablation without the policy '
  'annotations, and E8, the evaluation on crAPI, were not executed. Of E7, the five repeated timing runs were '
  'executed, but the CI workflow has not yet been run on GitHub Actions, so no CI run time is reported. This chapter '
  'reports only executed experiments. All raw findings, metrics and provenance notes are archived in the repository '
  'under evaluation/results/.')

H('OWASP ZAP on the benchmark and on VAmPI (E1, E2)', 2)
zap_alerts = {}
for run, z in zap_runs.items():
    for site in z.get('site', []):
        for a in site.get('alerts', []):
            cwe = str(a.get('cweid'))
            key = (a.get('alert') or a.get('name'), f'CWE-{cwe}' if cwe not in ('-1', '0', '') else '-')
            zap_alerts.setdefault(key, {})[run] = zap_alerts.setdefault(key, {}).get(run, 0) + len(a.get('instances', []))
P(f'ZAP completed its API scan on both targets and raised alerts, but none of them maps to an access-control or '
  f'authentication category (Table {{tab:zap}}). The alerts concern missing security headers, information disclosure '
  f'and client error responses. ZAP therefore detected 0 of the {b_zap["fn"]} vulnerable cases on the benchmark and 0 '
  f'of the {v_zap["fn"]} on VAmPI. Because it made no positive detections, its precision and F1 score are undefined, '
  f'and its false-positive rate is 0.000. One ZAP scan took {res(bench, ZAP)["durationMs"] / 1000:.1f} s on the '
  f'benchmark and {res(vampi, ZAP)["durationMs"] / 1000:.1f} s on VAmPI, including container start-up. In the '
  'VAmPI vulnerable run, one operation that made the server unresponsive in a first attempt was excluded from the '
  'imported specification; the failed attempt is archived and not scored.')
T('zap', 'Alerts raised by OWASP ZAP (number of alert instances per run)',
  ['Alert', 'CWE', *zap_runs.keys()],
  [[k[0], k[1], *[v.get(r, 0) for r in zap_runs]] for k, v in sorted(zap_alerts.items())],
  [6.0, 1.8, 2.05, 2.05, 2.05, 2.05],
  note='None of these alerts maps to an access-control category under the predefined CWE mapping.')

H('Role-aware tool and status-only baseline on the benchmark (E3, E4)', 2)


def comparison_rows(report, scopes):
    rows = []
    for sc in scopes:
        for r in report['results']:
            x = r['metrics']['confirmed'].get(sc)
            if x:
                rows.append([SCOPE_LABEL[sc], r['name'], x['tp'], x['fp'], x['tn'], x['fn'], f3(x['precision']),
                             f3(x['recall']), f3(x['f1']), f3(x['falsePositiveRate'])])
    return rows


CMP_HEAD = ['Scope', 'Approach', 'TP', 'FP', 'TN', 'FN', 'Precision', 'Recall', 'F1', 'FPR']
CMP_W = [2.5, 2.3, 0.9, 0.9, 1.1, 1.0, 2.0, 1.45, 1.3, 1.35]
P(f'Both scanner runs sent the same {REQ} requests to the vulnerable build. Table {{tab:bench}} gives the results. '
  f'The role-aware tool detected all {b_ra["tp"]} vulnerable cases and reported no false positives: precision, '
  f'recall and F1 were {f3(b_ra["precision"])} and the false-positive rate {f3(b_ra["falsePositiveRate"])}, both for '
  f'BOLA and BFLA ({bp_ra["tp"]} of {bp_ra["tp"] + bp_ra["fn"]}) and over all categories. The status-only baseline '
  f'detected the same {b_so["tp"]} cases, so its recall was also {f3(b_so["recall"])}, but it reported '
  f'{b_so["fp"]} false positives. Its overall precision was {f3(b_so["precision"])}, its F1 score '
  f'{f3(b_so["f1"])} and its false-positive rate {f3(b_so["falsePositiveRate"])}. For BOLA and BFLA alone, its '
  f'precision was {f3(bp_so["precision"])} and its false-positive rate {f3(bp_so["falsePositiveRate"])} '
  f'({bp_so["fp"]} of {bp_so["fp"] + bp_so["tn"]} secure cases flagged). Figures {{fig:bprim}} and {{fig:ball}} show '
  'the comparison.')
T('bench', 'Benchmark API (vulnerable build): detection quality by approach', CMP_HEAD,
  comparison_rows(bench, ['PRIMARY', 'BOLA', 'BFLA', 'SECONDARY', 'OVERALL']), CMP_W,
  note='Threshold: confirmed findings; the confirmed+potential threshold gives identical values. n/a = undefined because the denominator is zero.')
F('bprim', FIG / 'fig-benchmark-primary.png', 'Detection quality for BOLA and BFLA on the benchmark API, by approach (E1, E3, E4)')
F('ball', FIG / 'fig-benchmark-overall.png', 'Detection quality over all categories on the benchmark API, by approach (E1, E3, E4)')
fp_ops = [f"{c['method']} {c['path']}" for c in per_case if c['vulnerable'] == 'false' and c[SO] != 'not reported']
P(f'The per-case results show where the false positives of the baseline come from. {so_fp_scored} of them are the '
  f'{len(TN_PATTERNS)} true-negative patterns of Table {{tab:tn}}: the baseline flagged every one of them '
  f'({", ".join(fp_ops)}), while the ownership-differential oracle classified each correctly as denied. The public '
  'document was recognised through the configured public indicator, the ignored path identifier through the '
  'attacker\'s own identity in the response, the soft denials through their response body, the unapplied 202 '
  'through the owner\'s re-read, and the role-filtered view through its comparison with the administrator\'s '
  'response.',
  f'The other {so_fp_unlisted} false positives of the baseline are authentication and token findings on operations '
  f'that already have a broader authentication flaw, for example an "expired token accepted" finding on an endpoint '
  f'that requires no token at all. These cases are excluded from scoring by the root-cause rule, and the scorer '
  f'counts findings on them as false positives. As described in Section 4.4, the role-aware mode filters such '
  f'findings and the status-only mode does not, so these {so_fp_unlisted} false positives are caused by the filter '
  f'rather than by the decision rule. If they were disregarded, the baseline\'s overall precision would be '
  f'{so_alt_precision:.3f} ({b_so["tp"]} true and {so_fp_scored} false positives). This figure is a sensitivity '
  'reading derived from the archived findings, not a separate experiment. The BOLA and BFLA results are not '
  'affected, because the root-cause rule applies only to authentication categories.',
  f'On the patched build, where every flaw is fixed, the role-aware tool sent {patched_findings["meta"]["requests"]} '
  f'requests and reported {len(patched_findings["findings"])} findings, so it would let the patched build pass a CI '
  'gate. ZAP also reported no access-control findings on the patched build.')

H('Role-aware tool and status-only baseline on VAmPI (E5)', 2)
P(f'VAmPI has three vulnerable cases in its vulnerable mode: two BOLA cases and one BFLA case. Each scanner run sent '
  f'{res(vampi, RA)["requests"]} requests. Table {{tab:vampi}} and Figure {{fig:vprim}} give the results. The '
  f'role-aware tool detected {v_ra["tp"]} of {v_ra["tp"] + v_ra["fn"]} cases without false positives: precision '
  f'{f3(v_ra["precision"])}, recall {f3(v_ra["recall"])}, F1 {f3(v_ra["f1"])}. It detected the BOLA on '
  'GET /books/v1/{book_title}, where the response exposes the owner\'s user name, and the BFLA on the unauthenticated '
  'debug endpoint GET /users/v1/_debug. It missed the cross-user password change on '
  'PUT /users/v1/{username}/password. VAmPI answers this request with 204 No Content and offers no endpoint that '
  'reads a password back. For state verification the tool re-read the victim\'s user record through '
  'GET /users/v1/{username}, which does not contain the password, found it unchanged and therefore classified the '
  'test as denied. The archived test record confirms this verdict, which is why the case is missing at both '
  'thresholds.',
  f'The status-only baseline detected all {v_so["tp"]} cases with precision {f3(v_so["precision"])} and recall '
  f'{f3(v_so["recall"])}. On VAmPI it raised no false positive because VAmPI\'s vulnerable mode contains almost no '
  'legitimate success responses to forbidden requests. ZAP detected none of the three cases. In VAmPI\'s patched '
  'mode, the role-aware tool reported exactly one finding, the debug endpoint, which VAmPI leaves open in both modes '
  'and which the patched-mode ground truth labels vulnerable.')
T('vampi', 'VAmPI (vulnerable mode): detection quality by approach', CMP_HEAD,
  comparison_rows(vampi, ['PRIMARY', 'BOLA', 'BFLA', 'OVERALL']), CMP_W,
  note='Threshold: confirmed findings. VAmPI has no vulnerable authentication cases, so the secondary scope is omitted.')
F('vprim', FIG / 'fig-vampi-primary.png', 'Detection quality for BOLA and BFLA on VAmPI, by approach (E2, E5)')

H('Cost of a scan and CI suitability (E7, RQ3)', 2)
P(f'Table {{tab:rq3}} shows the five timed runs of the role-aware tool on the benchmark API. Every run sent exactly '
  f'{REQ} HTTP requests, including the login requests, owner baselines and state verification reads. The mean '
  f'duration was {t_mean:.0f} ms with a standard deviation of {t_sd:.0f} ms (n = {len(timing)}, population '
  f'standard deviation), against a local Docker target. For comparison, a single ZAP API scan of the same API took '
  f'{res(bench, ZAP)["durationMs"] / 1000:.1f} s, although this figure includes the start-up of the ZAP container and '
  'is not a like-for-like measurement. On VAmPI one role-aware scan took '
  f'{res(vampi, RA)["durationMs"]} ms and {res(vampi, RA)["requests"]} requests.',
  'The tool runs without interaction, reads all inputs from files and environment variables, writes its reports to '
  'files and signals the result through its exit code. The repository contains a GitHub Actions workflow that uses '
  'these properties. The workflow was validated locally, but it has not yet been run on GitHub, so the time a full '
  'pipeline run takes, including building and starting the containers, is not yet known.')
T('rq3', 'Cost of one scan of the benchmark API (role-aware oracle, n = 5)',
  ['Run', 'Requests', 'Duration (ms)'],
  [[t['run'], t['requests'], t['ms']] for t in timing] + [['Mean ± SD', REQ, f'{t_mean:.0f} ± {t_sd:.0f}']],
  [4.0, 6.0, 6.0], note='Source: evaluation/results/2026-11-21-scanner-test-api/rq3-timing.csv. Benchmark reset between runs.')

# ============================================================================== 6 DISCUSSION
H('Discussion')
H('Answer to RQ1: detecting BOLA and BFLA with a specification and several accounts', 2)
P('The tool shows that BOLA and BFLA can be detected automatically when three kinds of knowledge are combined: '
  'the operation inventory from the OpenAPI specification, the intended policy of each operation, and the identities '
  'of several accounts with different roles. The specification makes it possible to generate valid requests for '
  'every operation. The policy tells the tool which requests should be refused: cross-user requests to owner-only '
  'operations and cross-role requests to role-restricted operations. The accounts make it possible to send these '
  'requests with real sessions and to know whose data a response contains.',
  'The second part of the answer concerns the decision. Sending forbidden requests is not enough; the tool must '
  'decide whether a response proves a vulnerability. The ownership-differential oracle does this from evidence in '
  'the response and in the state of the API: owner identifiers, a comparison with the owner\'s own response, and a '
  're-read of the object after a write or delete. On the benchmark this combination classified all '
  f'{b_ra["tp"] + b_ra["tn"]} scored cases correctly.',
  'The answer comes with conditions. The policy must be known, either from annotations in the specification or from '
  'configuration. Ownership must be recognisable, through owner fields in responses or through comparison with the '
  'owner\'s view. Public objects must be described by a configured indicator. And the effect of a write must be '
  'observable through the API. VAmPI showed that the last condition does not always hold. These conditions are the '
  'price of the oracle\'s precision: the tool moves knowledge that a human tester would apply implicitly into '
  'explicit configuration.')
H('Answer to RQ2: comparison with OWASP ZAP and a status-only approach', 2)
P(f'Compared with OWASP ZAP the difference is categorical. ZAP\'s standard API scan detected none of the '
  f'{b_zap["fn"]} benchmark flaws and none of the {v_zap["fn"]} VAmPI flaws, because its rules do not test whether '
  'one user can access another user\'s objects or functions. This does not mean ZAP is a poor tool; it means that '
  'broken access control lies outside what a single-user DAST scan is designed to find, which is consistent with the '
  'literature reviewed in Chapter 2. A fairer comparison with ZAP\'s manual Access Control Testing add-on remains '
  'open.',
  f'Compared with the status-only approach, the two oracles had the same recall on the benchmark, which is expected '
  f'because they evaluated the same requests: every true vulnerability produced a 2xx response. The difference was '
  f'in precision. On BOLA and BFLA, the status-only oracle flagged {bp_so["fp"]} of {bp_so["fp"] + bp_so["tn"]} '
  f'secure cases (precision {f3(bp_so["precision"])}), and all of them were the deliberate true-negative patterns; '
  f'the ownership-differential oracle flagged none. Over all categories the status-only precision fell to '
  f'{f3(b_so["precision"])}, but, as Section 5.3 showed, {so_fp_unlisted} of its {b_so["fp"]} false positives come '
  'from the root-cause filter being active only in role-aware mode, so the like-for-like comparison of the two '
  f'decision rules is the BOLA and BFLA scope, or the overall precision of {so_alt_precision:.3f} that results when '
  'those findings are disregarded. Either way, the ownership-aware decision removed every false positive on the '
  'benchmark without losing a detection.',
  f'Why does the status-only precision collapse on the benchmark but stay at {f3(v_so["precision"])} on VAmPI? The '
  'status-only rule is only as precise as the target API is simple. It fails exactly where a protected operation '
  'legitimately returns a success status, and the benchmark was designed to contain such operations, while VAmPI\'s '
  'vulnerable mode contains almost none. The status-only rule even achieved a higher recall on VAmPI, because it '
  'flagged the blind password change from its 204 status. That success is fragile: in VAmPI\'s patched mode the '
  'same request also returns 204 while changing only the caller\'s own password, so the status code cannot '
  'separate the vulnerable from the correct behaviour. The two targets together therefore show that the precision '
  'of the status-only approach depends on the target API, whereas the ownership-differential oracle kept precision '
  f'{f3(b_ra["precision"])} on both. Real APIs are likely to contain public objects, soft denials, asynchronous '
  'processing and filtered views, so the benchmark is arguably closer to practice than VAmPI in this respect, but '
  'this claim would need evaluation on more APIs.')
H('Answer to RQ3: cost and CI suitability', 2)
P(f'A complete scan of the {ops["total"]}-operation benchmark sent {REQ} requests and took about '
  f'{t_mean / 1000:.1f} s on average, with little variation between runs. The number of requests is deterministic '
  'because the test plan is generated deterministically from the specification, the configuration and the seed '
  'data. These figures make the tool cheap enough to run on every commit, which is the condition for using it as a '
  'regression check in CI. The tool already has the properties CI needs: unattended operation, file-based input and '
  'output, redacted reports and an exit code that gates the pipeline. What is not yet demonstrated is an actual run '
  'on GitHub Actions; until that run is made, the answer to the second half of RQ3 rests on the design and on local '
  'validation, not on a measured pipeline. The request count grows with the number of operations, accounts, roles '
  'and discovered objects, so larger APIs will need proportionally more requests; the configurable request budget '
  'and throttling exist for that reason.')
H('Limitations of the tool', 2)
P('The most important limitation of ownership-differential detection is observability. The tool can only confirm '
  'what it can see through the API. A write whose effect cannot be read back, such as VAmPI\'s password change, is '
  'invisible to state verification. The VAmPI miss also exposed a weakness in the oracle\'s reasoning: it treats an '
  'unchanged re-read as evidence that the write was not applied, which is only valid when the re-read representation '
  'contains the field that was written. Where it does not, a more cautious oracle would classify the test as '
  'inconclusive and report it as a potential finding for manual review instead of as denied. Blind writes could '
  'also be confirmed by a side channel, for example by logging in with the changed password, but that requires '
  'API-specific knowledge.',
  'The second limitation is the knowledge the tool needs. The benchmark specification carries x-access-control '
  'annotations, and the benchmark configuration names the owner fields and a public-object indicator. For VAmPI, the '
  'access rules and ownership fields had to be written into the configuration, and one ownership field had to be '
  'added after a first run before the tool could identify the victim\'s books. In a real project, writing this '
  'configuration is part of the cost of using the tool. The planned ablation E6, which withholds the annotations, '
  'would show how much detection depends on them.',
  'Third, the tool tests one attacker-victim pair per role and the objects it discovers through list endpoints. '
  'Objects that cannot be listed, identifiers that cannot be guessed, multi-step workflows and other API styles such '
  'as GraphQL are outside its current reach, as is broken object property level authorization.')
H('Threats to validity', 2)
P('Internal validity. The benchmark, its ground truth and the tool were designed by the same author, which creates '
  'a risk that the tool was shaped to fit the benchmark. Three measures reduce this risk: the ground truth was fixed '
  'before the tool was run and is generated from documented rules; the patched build provides an independent '
  'true-negative dataset; and VAmPI, an API designed by others, was used as an external check. However, the risk was '
  'not eliminated. The detection engine was corrected after a run in which it produced one false positive on the '
  'benchmark (its root-cause map omitted one subsumption between token categories), and the VAmPI configuration was '
  'extended with an ownership field after a run. Both changes were justified by documented design rules and by the '
  'API\'s actual response format, but they were made with knowledge of the evaluation data, so the perfect scores on '
  'the benchmark must be read as results on development data rather than on unseen data.',
  'A second internal threat is the asymmetry between the oracles described in Section 5.3: the root-cause filter is '
  'applied only in role-aware mode. The statement that the two oracles differ only in their decision rule therefore '
  'holds exactly for BOLA and BFLA, but not for the authentication categories. The thesis reports both the scored '
  'figure and the sensitivity figure for this reason. A cleaner design would apply the filter to both modes.',
  'Construct validity. Case-level scoring counts a case as detected when at least one finding matches it, and counts '
  'findings outside the scored cases as false positives. Other reasonable rules, such as ignoring findings on '
  'excluded cases or counting findings instead of cases, give different numbers, as the sensitivity figure shows. '
  'The thresholds made no difference in the executed runs.',
  f'External validity. The number of vulnerable cases is small: {GTT["vulnerable"]} on the benchmark, of which '
  f'{bp_ra["tp"] + bp_ra["fn"]} are BOLA or BFLA, and {VGT["vulnerable"]} on VAmPI. A single missed case changes '
  'recall substantially, as VAmPI shows, so the ratios should be read together with the raw counts. Both targets '
  'are small, synthetic APIs, and the benchmark specification contains policy annotations that real APIs usually '
  'lack. crAPI, which would have added a larger and more realistic target, was not evaluated. The results therefore '
  'show that the approach works on APIs that meet its assumptions; they do not show how often real APIs meet them.',
  'Reliability. The timing results come from five runs on one machine against a local target and do not include '
  'network latency. The ZAP comparison used its standard single-user scan; a different ZAP configuration could '
  'detect some flaws. All raw outputs, configurations and scripts are archived so that the experiments can be '
  'repeated.')
H('Critical evaluation of the use of artificial intelligence', 2)
P('Artificial intelligence was used extensively in this work, and the statement before the list of references '
  'records the tools, purposes and dates. Claude Code (Anthropic) was used to scaffold the repository and to '
  'implement the benchmark API, the ground-truth generator, the evaluation pipeline, the ZAP adapter and runner, the '
  'reporting module, the CI workflow, the results dashboard and the thesis tables, and to draft this report. Google '
  'Gemini was used to produce the detection engine, which was then reviewed and corrected with Claude Code. '
  '[Author: describe here your own role precisely: which design decisions, reviews, corrections and experiments you '
  'carried out yourself, and how you checked the AI output.]',
  'AI assistance made it possible to build a larger and better-tested artifact in the available time than would '
  'otherwise have been feasible: the repository contains a benchmark with a machine-checked ground truth, 80 '
  'automated tests and a reproducible evaluation pipeline. It also helped to keep documentation, data and results '
  'consistent, because tables and figures are generated from the archived results rather than typed in.',
  'The use of AI also created risks that had to be managed, and some of them materialised. AI-generated code can be '
  'wrong while looking plausible: the engine produced by Gemini contained an error in its root-cause map that caused '
  'a false positive, which was only found because the output was scored against an independent ground truth. The '
  'same review did not notice that the root-cause filter was applied only in role-aware mode, which weakens the '
  'claim that the oracles differ only in their decision rule; this was identified later, while this draft was being '
  'prepared from the archived data. The lesson is that automated tests and a ground truth are necessary but not '
  'sufficient checks on AI-generated code, and that claims about the code must be verified against the code itself.',
  'A further risk concerns the research process. When the same AI system builds the benchmark, the tool and the '
  'evaluation, there is a danger that all three share the same assumptions, which strengthens the author-bias threat '
  'discussed above. Fixing the ground truth and the ZAP configuration before running the tool, and using VAmPI as an '
  'external target, were the main safeguards. For the written report, AI-produced text can contain inaccurate '
  'statements about sources. For this reason the bibliography was limited to entries whose existence was checked '
  'against registry records, entries that could not be checked are marked, and every cited claim must be checked '
  'against the original source by the author. Finally, the thesis is assessed on the student\'s own understanding '
  'and written expression. The AI-produced draft is therefore a starting point that the author has reviewed, '
  'corrected and rewritten, and the analysis and conclusions are the author\'s own responsibility. [Author: revise '
  'this section to reflect your actual process and your own assessment.]')

# ============================================================================== 7 CONCLUSION
H('Conclusion')
P(f'This thesis set out to design, implement and evaluate a tool that detects broken object level and broken '
  f'function level authorization in REST APIs automatically. Following Design Science Research, it produced a '
  f'role-aware testing tool in JavaScript, a benchmark API with {GTT["vulnerable"]} injected flaws, deliberate '
  f'true-negative patterns and a fixed ground truth, and an evaluation pipeline that scores any tool against that '
  f'ground truth. On the benchmark, the tool found all flaws with no false positives, whereas a status-only oracle '
  f'with the same requests reached the same recall at clearly lower precision and OWASP ZAP\'s standard API scan '
  f'found none of the flaws. On VAmPI the tool kept full precision but missed one flaw whose effect cannot be '
  f'observed through the API. A scan of the benchmark took about {t_mean / 1000:.1f} seconds and {REQ} requests.',
  'The contributions of the thesis are, first, a working design for role-aware detection that separates test '
  'generation from the decision, so that decision rules can be compared on identical requests; second, an '
  'ownership-differential oracle that combines owner identifiers, owner baselines and state verification; third, a '
  'reusable benchmark with a flaw toggle, a patched build and true-negative patterns that measures false positives '
  'and not only detections; and fourth, empirical evidence that the precision of status-code-based detection '
  'depends on the target API, while the ownership-aware decision kept its precision on both targets.',
  'Several directions remain for future work. The ablation E6 should measure how detection changes when the policy '
  'annotations are withheld and the policy must come from configuration alone, or be inferred from the specification '
  'and observed behaviour. The evaluation should be extended to crAPI and to larger, more realistic APIs, ideally '
  'with ground truths created by people other than the tool\'s author. The CI workflow should be run on GitHub '
  'Actions to measure the cost of a full pipeline run. The tool itself could be extended to more than one '
  'attacker-victim pair per role, to side-channel confirmation of blind writes, to broken object property level '
  'authorization and to GraphQL APIs. Finally, a comparison with ZAP\'s Access Control Testing add-on and with '
  'Burp Suite extensions such as Autorize would place the tool more precisely among existing practical tools.')

# ================================================================================ AI + REFERENCES
AI_ENTRIES = [
    'Claude Code 2026. Anthropic. Claude Opus 5.5 and Claude Opus 4.8 (models recorded in the commit history). Used '
    'to scaffold the repository and to implement the benchmark API, ground truth, evaluation pipeline, OWASP ZAP '
    'adapter and runner, reporting module, CI workflow, results dashboard and thesis tables, to review and correct '
    'the detection engine, to run the experiments, and to draft this thesis report, 20-21 November 2026. '
    'https://claude.ai/code.',
    'Gemini 2026. Google. [Model version - to be completed by the author]. Used to write the role-aware detection '
    'engine (test generation, oracles, authentication probes) from the project\'s design documents, [exact dates - '
    'to be completed by the author] November 2026. https://gemini.google.com.',
]
REF_LIST = {
    'arcuri2019': 'Arcuri, A. 2019. RESTful API automated test case generation with EvoMaster. ACM Transactions on Software Engineering and Methodology [complete volume (issue), pages]. https://doi.org/10.1145/3293455. Accessed [date].',
    'atlidakis2019': 'Atlidakis, V., Godefroid, P. & Polishchuk, M. 2019. RESTler: stateful REST API fuzzing. In Proceedings of the 41st International Conference on Software Engineering (ICSE) [complete pages]. https://doi.org/10.1109/ICSE.2019.00083. Accessed [date].',
    'atlidakis2020': 'Atlidakis, V., Godefroid, P. & Polishchuk, M. 2020. Checking security properties of cloud service REST APIs. In IEEE International Conference on Software Testing, Validation and Verification (ICST) [complete pages]. https://doi.org/10.1109/ICST46399.2020.00046. Accessed [date].',
    'barabanov2022': 'Barabanov, A., Dergunov, D., Makrushin, D. & Teplov, A. 2022. Automatic detection of access control vulnerabilities via API specification processing. arXiv:2201.10833. https://doi.org/10.21681/2311-3456-2022-1-49-65. Accessed [date].',
    'bau2010': 'Bau, J., Bursztein, E., Gupta, D. & Mitchell, J. 2010. State of the art: automated black-box web application vulnerability testing. In IEEE Symposium on Security and Privacy [complete pages]. https://doi.org/10.1109/SP.2010.27. Accessed [date].',
    'corradini2022': 'Corradini, D., Zampieri, A., Pasqua, M., Viglianisi, E., Dallago, M. & Ceccato, M. 2022. Automated black-box testing of nominal and error scenarios in RESTful APIs. Software Testing, Verification and Reliability [complete volume (issue)]. https://doi.org/10.1002/stvr.1808. Accessed [date].',
    'doupe2010': 'Doupé, A., Cova, M. & Vigna, G. 2010. Why Johnny can\'t pentest: an analysis of black-box web vulnerability scanners. In Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA) [complete pages]. https://doi.org/10.1007/978-3-642-14215-4_7. Accessed [date].',
    'vampi': 'erev0s n.d. VAmPI: vulnerable REST API with OWASP Top 10 vulnerabilities. GitHub repository. https://github.com/erev0s/VAmPI. Accessed [date]. [UNVERIFIED - confirm title and author against the source.]',
    'fielding2000': 'Fielding, R. T. 2000. Architectural styles and the design of network-based software architectures. Doctoral dissertation. University of California, Irvine. [UNVERIFIED - confirm against the original and add a URL.]',
    'golmohammadi2023': 'Golmohammadi, A., Zhang, M. & Arcuri, A. 2023. Testing RESTful APIs: a survey. ACM Transactions on Software Engineering and Methodology [complete volume (issue)]. https://doi.org/10.1145/3617175. Accessed [date].',
    'hevner2004': 'Hevner, A. R., March, S. T., Park, J. & Ram, S. 2004. Design science in information systems research. MIS Quarterly [complete volume (issue), pages]. https://doi.org/10.2307/25148625. Accessed [date].',
    'rfc7519': 'Jones, M., Bradley, J. & Sakimura, N. 2015. JSON Web Token (JWT). RFC 7519. Internet Engineering Task Force. https://doi.org/10.17487/RFC7519. Accessed [date].',
    'kim2022': 'Kim, M., Xin, Q., Sinha, S. & Orso, A. 2022. Automated test generation for REST APIs: no time to rest yet. In Proceedings of the 31st ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA) [complete pages]. https://doi.org/10.1145/3533767.3534401. Accessed [date].',
    'owasp2023': 'OWASP Foundation 2023. OWASP API Security Top 10 - 2023. https://owasp.org/API-Security/. Accessed [date]. [UNVERIFIED web source - confirm the edition URL.]',
    'crapi': 'OWASP Foundation n.d. crAPI: completely ridiculous API. GitHub repository. https://github.com/OWASP/crAPI. Accessed [date]. [UNVERIFIED web source.]',
    'peffers2007': 'Peffers, K., Tuunanen, T., Rothenberger, M. A. & Chatterjee, S. 2007. A design science research methodology for information systems research. Journal of Management Information Systems [complete volume (issue), pages]. https://doi.org/10.2753/MIS0742-1222240302. Accessed [date].',
    'sandhu1996': 'Sandhu, R. S., Coyne, E. J., Feinstein, H. L. & Youman, C. E. 1996. Role-based access control models. Computer [complete volume (issue), pages]. https://doi.org/10.1109/2.485845. Accessed [date].',
    'rfc8725': 'Sheffer, Y., Hardt, D. & Jones, M. 2020. JSON Web Token best current practices. RFC 8725. Internet Engineering Task Force. https://doi.org/10.17487/RFC8725. Accessed [date].',
    'viglianisi2020': 'Viglianisi, E., Dallago, M. & Ceccato, M. 2020. RESTTESTGEN: automated black-box testing of RESTful APIs. In IEEE International Conference on Software Testing, Validation and Verification (ICST) [complete pages]. https://doi.org/10.1109/ICST46399.2020.00024. Accessed [date].',
    'zap': 'ZAP Development Team n.d. Zed Attack Proxy (ZAP). https://www.zaproxy.org/. Accessed [date]. [UNVERIFIED web source; version used in the experiments: 2.17.0.]',
}


def appendix_ops():
    """Appendix: ground-truth case list for BOLA/BFLA on the benchmark with the per-approach outcome."""
    rows = []
    for c in per_case:
        if c['category'] not in ('BOLA', 'BFLA'):
            continue
        def o(name):
            hit = c[name] != 'not reported'
            vul = c['vulnerable'] == 'true'
            return 'TP' if vul and hit else 'FN' if vul else 'FP' if hit else 'TN'
        rows.append([c['case_id'], f"{c['method']} {c['path']}", 'yes' if c['vulnerable'] == 'true' else 'no', o(RA), o(SO), o(ZAP)])
    return rows


# =========================================================================================== render
def render(cache):
    tno = fno = 0
    tables_helper = TableDocument.__new__(TableDocument)
    tables_helper.doc = doc
    tables_helper.table_no = 0
    numbers = {**{f'tab:{k}': v for k, v in TAB_NO.items()}, **{f'fig:{k}': v for k, v in FIG_NO.items()}}

    def resolve(text):
        out = re.sub(r'\{((?:tab|fig):\w+)\}', lambda mo: str(numbers[mo.group(1)]), text)
        assert '{tab:' not in out and '{fig:' not in out, out
        return out

    # front lists
    add_block_field('TOC \\o "1-3" \\h \\z \\u', cache.get('toc'), 'Update this field (F9) to build the table of contents.')
    heading_other('LIST OF FIGURES')
    add_block_field('TOC \\h \\z \\c "Figure"', cache.get('lof'), 'Update this field (F9) to build the list of figures.')
    heading_other('LIST OF TABLES')
    add_block_field('TOC \\h \\z \\c "Table"', cache.get('lot'), 'Update this field (F9) to build the list of tables.')
    page_break()

    for op in OPS:
        kind = op[0]
        if kind == 'h':
            doc.add_paragraph(op[1], style=STYLE[f'Heading {op[2]}'])
        elif kind == 'p':
            doc.add_paragraph(resolve(op[1]))
        elif kind == 't':
            _, key, caption, header, rows, widths, note = op
            tno += 1
            t = tables_helper.table(caption, header, rows, widths, note=resolve(note) if note else None)
            cap = para_obj(t._tbl.getprevious())  # replace the plain caption with a SEQ-numbered one
            for r in list(cap.runs):
                r._r.getparent().remove(r._r)
            cap.add_run('TABLE ')
            add_inline_field(cap, 'SEQ Table \\* ARABIC', str(tno))
            cap.add_run(f'. {caption}')
        elif kind == 'f':
            _, key, image, caption, width = op
            fno += 1
            p = doc.add_paragraph()
            p.paragraph_format.keep_with_next = True
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.left_indent = Cm(0)
            p.add_run().add_picture(str(image), width=Cm(width))
            cap = doc.add_paragraph(style=STYLE['Caption'])
            cap.add_run('Figure ')
            add_inline_field(cap, 'SEQ Figure \\* ARABIC', str(fno))
            cap.add_run(f'. {caption}')
    assert tno == len(TAB_NO) and fno == len(FIG_NO)

    # Appendix-referenced table is added at the end; the AI statement and references come first.
    page_break()
    heading_other('REFERENCES')
    refs_style = STYLE['Raferences']
    doc.add_paragraph('Artificial intelligence has been used in the work as follows:', style=refs_style)
    for e in AI_ENTRIES:
        doc.add_paragraph(e, style=refs_style)
    doc.add_paragraph('', style=refs_style)
    missing = [k for k in REFS if k not in _cited]
    assert not missing, f'references never cited: {missing}'
    for key in sorted(REF_LIST, key=lambda k: REF_LIST[k].lower()):
        doc.add_paragraph(REF_LIST[key], style=refs_style)

    page_break()
    heading_other('Appendix 1: BOLA AND BFLA CASES OF THE BENCHMARK AND THEIR OUTCOME PER APPROACH')
    tables_helper.table_no = tno
    t = tables_helper.table('Per-case outcome for BOLA and BFLA on the benchmark API (vulnerable build)',
                            ['Case', 'Operation', 'Vulnerable', RA, SO, 'ZAP'], appendix_ops(),
                            [2.6, 6.4, 1.8, 1.8, 1.8, 1.6],
                            note='TP = detected vulnerability, FP = flagged secure case, FN = missed vulnerability, TN = correctly not reported. '
                                 'Source: evaluation/results/2026-11-21-scanner-test-api/comparison/per-case.csv.')
    cap = para_obj(t._tbl.getprevious())
    for r in list(cap.runs):
        r._r.getparent().remove(r._r)
    cap.add_run('TABLE ')
    add_inline_field(cap, 'SEQ Table \\* ARABIC', str(tno + 1))
    cap.add_run('. Per-case outcome for BOLA and BFLA on the benchmark API (vulnerable build)')

    # Ask Word to refresh fields on open (TOC page numbers may shift after the author's edits).
    settings = doc.settings.element
    uf = settings.find(qn('w:updateFields'))
    if uf is None:
        uf = OxmlElement('w:updateFields')
        settings.append(uf)
    uf.set(qn('w:val'), 'true')


def parse_cache(lo):
    """Converts LibreOffice index text into cached field results for the second pass."""
    out = {}
    for ix, key in zip(lo['indexes'], ['toc', 'lof', 'lot']):
        lines = [ln for ln in ix['text'].split('\n') if ln.strip()]
        if lines and lines[0].strip().upper() in ('CONTENTS', 'TABLE OF CONTENTS', 'LIST OF FIGURES', 'LIST OF TABLES', 'ILLUSTRATION INDEX', 'INDEX OF TABLES'):
            lines = lines[1:]
        entries = []
        for ln in lines:
            if key == 'toc':
                num = ln.split('\t')[0]
                level = num.count('.') + 1 if re.fullmatch(r'\d+(\.\d+)*', num) else 1
                entries.append((f'toc {min(level, 3)}', ln))
            else:
                entries.append(('table of figures', ln))
        out[key] = entries
    return out


def build(cache, pages):
    render(cache)
    if pages:
        set_formtext(PAGES_CELL, pages)
    doc.save(str(OUT))


def lo_pass(src):
    with tempfile.TemporaryDirectory() as tmp:
        js = Path(tmp) / 'lo.json'
        subprocess.run([sys.executable, str(HERE / 'lo_update.py'), str(src), str(PDF), str(js)], check=True)
        return json.loads(js.read_text())


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--cache', help=argparse.SUPPRESS)  # internal: second pass
    ap.add_argument('--pages', help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.cache is None:
        # Pass 1: build, let LibreOffice refresh the lists and count pages, then rebuild in a fresh process.
        build({}, None)
        lo = lo_pass(OUT)
        with tempfile.TemporaryDirectory() as tmp:
            cache_file = Path(tmp) / 'cache.json'
            cache_file.write_text(json.dumps(parse_cache(lo)))
            subprocess.run([sys.executable, __file__, '--cache', str(cache_file), '--pages', str(lo['pages'])], check=True)
    else:
        cache = {k: [tuple(e) for e in v] for k, v in json.loads(Path(args.cache).read_text()).items()}
        build(cache, f'{args.pages} pages, 1 appendix')
        lo2 = lo_pass(OUT)
        if str(lo2['pages']) != args.pages:
            print(f'Note: page count changed from {args.pages} to {lo2["pages"]} after caching the lists.')
        print(f'Wrote {OUT.relative_to(ROOT)} and {PDF.relative_to(ROOT)}: {lo2["pages"]} pages, '
              f'{len(TAB_NO) + 1} tables, {len(FIG_NO)} figures, {len(_cited)} cited sources')
