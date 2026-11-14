"""Demo Mode redaction, for templates outside the verification result.

The Verify page masks a citizen's details server-side before they are
rendered (`apply_demo_mask`). The administration pages have the same problem
with different data: `/app/admin/` lists real operators by name and National
ID, and `/app/setup/` shows the URLs and client IDs the site signs in
against. An operator presenting to an audience has to be able to open those
pages without putting any of it on a projector.

Each filter takes the flag rather than reading it itself, so a template that
forgets to pass it renders the value unmasked and visibly wrong, rather than
silently masking for everybody.

    {% load demo %}
    {{ member.full_name|demo_name:demo_mode }}
    {{ member.national_id_formatted|demo_id:demo_mode }}
    {{ site.sso_issuer|demo_url:demo_mode }}

**These redact for the screen only.** What is stored stays true, exactly as a
demo verification is still logged truthfully. The other half of that promise
is `is_demo_masked()`: every form whose fields these touch has to refuse to
save a value that came back masked, or a presentation would overwrite a real
client ID with bullets.
"""

from django import template

from verify.views.helpers import mask_identifier, mask_name, mask_url

register = template.Library()


def _guard(masker):
    def filter_fn(value, active=False):
        if not active or value is None or not str(value).strip():
            return value
        return masker(value)
    return filter_fn


#: A person's name, kept as far as its first word.
register.filter("demo_name", _guard(mask_name))

#: A National ID, client ID or serial number, kept to its last character.
register.filter("demo_id", _guard(mask_identifier))

#: A URL, kept as far as its scheme.
register.filter("demo_url", _guard(mask_url))
