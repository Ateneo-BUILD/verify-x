import time

from django.conf import settings

from accounts.models import User


def branding(request):
    """The site's own name and footer logos; see verify/branding.py."""
    from verify.branding import footer_logos
    return {
        "site_title": settings.SITE_TITLE,
        "footer_label": settings.SITE_FOOTER_LABEL,
        "footer_logos": footer_logos(),
    }


def app_version(request):
    if settings.DEBUG:
        return {"APP_VERSION": str(int(time.time()))}
    return {"APP_VERSION": getattr(settings, "APP_VERSION", "1")}


def org_context(request):
    """The organization banner, the nav gates, and the context strip.

    Reads the session directly rather than calling _get_session_user(): that
    helper bridges a Django staff login into a verify User and CREATES the row
    if it is missing, which would be a write on every rendered GET. By the
    time a template renders, the view has already run and stamped the session,
    so reading it here is enough.
    """
    user_id = request.session.get("verify_user_id")
    if not user_id:
        return {}

    # Imported here: helpers imports from accounts.models, and this module is
    # loaded while settings are still being read.
    from verify.views.helpers import (_available_organizations,
                                      _current_organization, _is_org_admin,
                                      _location_name, demo_mode_for, mask_name)

    user = User.objects.filter(pk=user_id).first()
    if user is None:
        return {}

    org = _current_organization(request, user)
    location_count = (org.locations.filter(is_active=True).count() if org else 0)
    org_count = _available_organizations(user).count()

    # Demo Mode reaches every signed-in page, not just Verify: the operator's
    # own name sits in the top-right corner of all of them, and the admin
    # pages list other people by name and National ID. Resolved here so no
    # view has to remember to pass it, and so a page that forgets to USE it
    # is the only way to leak.
    demo_mode = demo_mode_for(user)

    return {
        "demo_mode": demo_mode,
        # What the corner shows: short_name, which is one given word and the
        # whole surname -- a badge for whose session this is, not the record
        # of who they are that the document footer and the member lists
        # carry. Masked with the same rule as a citizen's given name on the
        # Verify page -- first word kept, the rest redacted -- so the
        # operator can still tell it is their own session.
        "session_display_name": (mask_name(user.short_name) if demo_mode
                                 else user.short_name),
        "session_user": user,
        "current_org": org,
        "current_location_name": _location_name(
            org, request.session.get("operator_location", "")) if org else "",
        "is_org_admin": _is_org_admin(user, org),
        "is_site_admin": user.is_site_admin,
        "is_all_org_admin": user.is_all_org_admin,
        # Publishing or starting an organization's key.
        "may_switch_keys": user.switches_signing_keys,
        # Nothing to change when there is only one possible answer, so the
        # context strip and the switcher stay off the page entirely.
        "can_switch_context": org_count > 1 or location_count > 1,
    }
