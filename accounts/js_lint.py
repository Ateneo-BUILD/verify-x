"""Scanners for the two template mistakes that fail silently here.

Neither shows up as an error -- the page renders, it is just wrong.

1. A JS string literal that runs off the end of a line. A JS string cannot
   span lines; one that does is a syntax error that takes out every handler
   in its <script> block, not just the statement it appears in -- a page's
   logo upload, member controls and copy button all at once.

2. A Django `{# #}` comment spanning more than one line. `{# #}` is
   SINGLE-LINE ONLY -- the parser does not close it across a newline, so the
   comment renders to the page as visible text, in the header of every
   page that includes it. Use `{% comment %}...{% endcomment %}` for
   anything longer than one line.
"""
import re


def script_blocks(src):
    for m in re.finditer(r'<script([^>]*)>(.*?)</script>', src, re.S | re.I):
        attrs = m.group(1).lower()
        if 'type=' in attrs and 'javascript' not in attrs:
            continue          # json / text-plain data blocks are not code
        yield src[:m.start(2)].count('\n') + 1, m.group(2)


def unterminated(js, first_line):
    bad = []
    in_block_comment = False
    in_template = False
    for offset, line in enumerate(js.split('\n')):
        quote = None
        i = 0
        while i < len(line):
            ch = line[i]
            if in_block_comment:
                if line.startswith('*/', i):
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_template:
                if ch == '\\':
                    i += 2
                    continue
                if ch == '`':
                    in_template = False
                i += 1
                continue
            if quote:
                if ch == '\\':
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue
            if line.startswith('//', i):
                break
            if line.startswith('/*', i):
                in_block_comment = True
                i += 2
                continue
            if ch == '`':
                in_template = True
                i += 1
                continue
            if ch in '"\'':
                quote = ch
                i += 1
                continue
            i += 1
        if quote:
            bad.append((first_line + offset, line.strip()[:90]))
    return bad


def multiline_django_comments(src):
    """Report `{# ... #}` comments that span lines, or are never closed.

    Both render to the page as visible text. Returns (line, text) pairs.
    """
    bad = []
    for match in re.finditer(re.escape("{#"), src):
        line_no = src.count(chr(10), 0, match.start()) + 1
        rest = src[match.start():]
        close = rest.find("#}")
        first_line = rest.split(chr(10))[0][:70]
        if close < 0:
            bad.append((line_no, "never closed: " + first_line))
        elif chr(10) in rest[:close]:
            bad.append((line_no, first_line))
    return bad
