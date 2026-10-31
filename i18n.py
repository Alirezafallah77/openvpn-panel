"""Browser preferences and presentation-only calendar conversion.

Translation happens on template source (never rendered user content). Catalog keys
are the original Persian phrases, allowing a Persian-first UI without opaque IDs.
"""
from datetime import date, datetime, timezone
import json
from pathlib import Path
import re

import jdatetime
from flask import g, has_request_context
from jinja2 import BaseLoader

EN = json.loads((Path(__file__).parent/'locales/en.json').read_text())
PHRASES = re.compile(r'[\u0600-\u06ff\u200c]+(?:[\u0600-\u06ff\u200c\s۰-۹0-9،؛ٔـ‌«»؟٪\-]+[\u0600-\u06ff\u200c۰-۹0-9])?')
DIGITS = str.maketrans('۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩', '01234567890123456789')


def translate(text):
    if not isinstance(text, str) or not has_request_context() or g.get('language', 'fa') != 'en':
        return text
    def replace(match):
        value = match.group()
        phrase = value.strip()
        leading = value[:len(value)-len(value.lstrip())]
        trailing = value[len(value.rstrip()):]
        return leading + EN.get(phrase, phrase) + trailing
    return PHRASES.sub(replace, text)



class LocalizedLoader(BaseLoader):
    def __init__(self, loader): self.loader = loader
    def get_source(self, environment, template):
        source, filename, uptodate = self.loader.get_source(environment, template)
        return translate(source), filename, uptodate


def format_date(value, calendar=None):
    if not value: return translate('هنوز اجرا نشده')
    dt = datetime.fromtimestamp(value, timezone.utc)
    calendar = calendar or (g.get('calendar', 'gregorian') if has_request_context() else 'gregorian')
    if calendar == 'jalali':
        return jdatetime.datetime.fromgregorian(datetime=dt).strftime('%Y-%m-%d %H:%M:%S')+' UTC (Jalali)'
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')


def parse_date(value, calendar):
    """Strict calendar date -> Gregorian date, without touching DB/time zones."""
    value = value.translate(DIGITS)
    if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', value):
        raise ValueError('Use YYYY-MM-DD')
    year, month, day = map(int, value.split('-'))
    if calendar == 'jalali': return jdatetime.date(year, month, day).togregorian()
    if calendar != 'gregorian': raise ValueError('Unknown calendar')
    return date(year, month, day)


def date_input(value):
    dt = datetime.fromtimestamp(value, timezone.utc).date()
    return (jdatetime.date.fromgregorian(date=dt) if g.get('calendar') == 'jalali' else dt).strftime('%Y-%m-%d')
