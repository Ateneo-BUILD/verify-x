"""What a CSV export may put in a cell, and in its file name.

Every export here is opened in a spreadsheet by an administrator, and a cell
a spreadsheet reads as a formula runs on that administrator's machine. The
text in these exports is written by other people: an operator's typed name
for a failed verification, the upstream's answer, a phone's own log. So no
cell leaves without passing through `cell()`.
"""

from datetime import datetime

#: What a spreadsheet reads as the start of a formula.
FORMULA_LEADS = ("=", "+", "-", "@", "\t", "\r")


def cell(value):
    """`value` as text, with a leading apostrophe if it would be a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_LEADS) else text


def date_label(raw):
    """The date for the filename, or "all" -- never the raw parameter, which
    is the caller's to write and goes into a response header."""
    try:
        return datetime.strptime(raw or "", "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return "all"
