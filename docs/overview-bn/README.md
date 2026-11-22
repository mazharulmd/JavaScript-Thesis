# Bangla project overview (বাংলা ব্যাখ্যা-নথি)

`build_overview_bn.py` generates `Project-Overview-Bangla.docx` — a complete Bangla explainer of the
whole project (concepts, definitions, design, every experiment and result). It is a standalone
document, not the Savonia thesis.

Rebuild: `python3 docs/overview-bn/build_overview_bn.py`

Rendering uses the Noto Sans Bengali font; the .docx carries correct Bengali Unicode and sets a
Bengali font on every run, so Word/LibreOffice on any machine renders the conjuncts correctly.
