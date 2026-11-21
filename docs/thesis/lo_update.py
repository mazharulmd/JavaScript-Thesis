#!/usr/bin/env python3
"""LibreOffice (UNO) helper for build_thesis_draft.py.

Opens a .docx headless, updates every index (table of contents, list of figures, list of
tables) and every field, exports a PDF, and writes a JSON file with the page count and the
updated index text, so the build script can cache those results in the .docx itself.

Usage: python3 lo_update.py <in.docx> <out.pdf> <out.json>
Requires LibreOffice (soffice) and its Python UNO bridge (import uno).
"""
import json
import os
import subprocess
import sys
import tempfile
import time

import uno
from com.sun.star.beans import PropertyValue


def prop(name, value):
    p = PropertyValue()
    p.Name, p.Value = name, value
    return p


def main(src, pdf, out_json):
    port = 2002 + os.getpid() % 1000
    profile = tempfile.mkdtemp(prefix='lo-profile-')
    proc = subprocess.Popen(['soffice', '--headless', '--invisible', '--nologo', '--norestore',
                             f'-env:UserInstallation=file://{profile}',
                             f'--accept=socket,host=127.0.0.1,port={port};urp;'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        local = uno.getComponentContext()
        resolver = local.ServiceManager.createInstanceWithContext('com.sun.star.bridge.UnoUrlResolver', local)
        for _ in range(120):
            try:
                ctx = resolver.resolve(f'uno:socket,host=127.0.0.1,port={port};urp;StarOffice.ComponentContext')
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError('LibreOffice did not start')
        desktop = ctx.ServiceManager.createInstanceWithContext('com.sun.star.frame.Desktop', ctx)
        doc = desktop.loadComponentFromURL(uno.systemPathToFileUrl(os.path.abspath(src)), '_blank', 0,
                                           (prop('Hidden', True),))
        # Two rounds: page numbers in the indexes can shift once the indexes themselves are filled.
        for _ in range(2):
            doc.getTextFields().refresh()
            idx = doc.getDocumentIndexes()
            for i in range(idx.getCount()):
                idx.getByIndex(i).update()
            doc.refresh()
        indexes = []
        idx = doc.getDocumentIndexes()
        for i in range(idx.getCount()):
            ix = idx.getByIndex(i)
            indexes.append({'service': ix.getImplementationName(), 'title': ix.Title,
                            'text': ix.getAnchor().getString()})
        controller = doc.getCurrentController()
        pages = controller.getPropertyValue('PageCount')
        doc.storeToURL(uno.systemPathToFileUrl(os.path.abspath(pdf)), (prop('FilterName', 'writer_pdf_Export'),))
        doc.close(True)
        with open(out_json, 'w') as f:
            json.dump({'pages': pages, 'indexes': indexes}, f, indent=1)
    finally:
        try:
            desktop.terminate()
        except Exception:
            pass
        proc.terminate()
        proc.wait(timeout=30)


if __name__ == '__main__':
    main(*sys.argv[1:4])
