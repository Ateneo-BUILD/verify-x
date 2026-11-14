"""
URL configuration for verify project.
"""
from django.contrib import admin
from django.http import JsonResponse
from django.urls import path

from accounts import throttle

from . import views


def health_check(request):
    return JsonResponse({"status": "ok"})


# "VIEW SITE" in the Django admin header. The default is "/", which is the
# login page and bounces a signed-in admin straight back to /app/ anyway;
# point it at the app itself. _get_session_user() bridges a Django staff or
# superuser to a verify User marked as a site admin, so /app/ renders for
# them without a separate eVerify login.
admin.site.site_url = "/app/"

# Django admin's login takes a password and opens a site-administrator session
# through the bridge, so its POSTs are limited per address like the other ways
# in. Wrapped before admin.site.urls is read below, which is when the login
# route is built.
admin.site.login = throttle.admin_login(admin.site.login)


urlpatterns = [
    path("health/", health_check, name="health-check"),
    path("", views.home, name="home"),

    # Which organization, and which of its locations, this session acts for.
    # Reached after every sign-in; it sends single-organization operators
    # straight on without showing them anything.
    path("choose/", views.choose, name="choose"),
    path("choose/switch/", views.switch, name="switch_context"),

    path("app/", views.app, name="app"),
    path("app/document/", views.document, name="document"),
    # The document page's User Records card. Whose records comes from the
    # session's verification, never from the request.
    path("app/user-records/", views.user_records_api, name="user_records"),
    path("validate/", views.validate, name="validate"),
    path("app/setup/", views.setup, name="setup"),
    # Credential signing: what verify may do. Site admins only; publishing
    # and everything after it is a command on the signer host, except an
    # organization's key where the host's policy lets the site publish it.
    path("app/setup/signing/pause/", views.signing_pause, name="signing_pause"),
    path("app/setup/signing/keys/<int:key_id>/suspend/", views.signing_suspend,
         name="signing_suspend"),
    path("app/setup/signing/keys/<int:key_id>/certificate/",
         views.signing_certificate, name="signing_certificate"),
    path("app/setup/signing/keys/<int:key_id>/request.csr",
         views.signing_csr, name="signing_csr"),
    path("app/setup/signing/keys/<int:key_id>/discard/",
         views.signing_discard, name="signing_discard"),
    path("app/setup/signing/keys/<int:key_id>/publish/",
         views.signing_publish, name="signing_publish"),
    path("app/setup/signing/keys/<int:key_id>/activate/",
         views.signing_activate, name="signing_activate"),
    # Only where the signer's policy sets `site_controls_all_keys`:
    # withdraw, unsuspend and resume from the site.
    path("app/setup/signing/keys/<int:key_id>/withdraw/",
         views.signing_withdraw, name="signing_withdraw"),
    path("app/setup/signing/keys/<int:key_id>/unsuspend/",
         views.signing_unsuspend, name="signing_unsuspend"),
    path("app/setup/signing/resume/", views.signing_resume,
         name="signing_resume"),
    path("app/setup/signing/organizations/<int:org_id>/generate/",
         views.signing_generate, name="signing_generate"),
    path("app/setup/signing/organizations/<int:org_id>/request/",
         views.signing_request, name="signing_request"),

    # The development store of whole eVerify responses, and the button that
    # empties it. 404 unless BOTH opt-ins are set -- a page that refused
    # politely would still tell anyone asking that this deployment keeps
    # identity records. See accounts/debug_store.py.
    path("debug-cleanup/", views.debug_cleanup, name="debug_cleanup"),
    # A synthetic verification, so a document can be looked at without
    # anybody having been verified to produce one. Same 404 rule, and
    # nothing about the identity comes from the request.
    path("debug-sample/", views.debug_sample, name="debug_sample"),
    # The Validate page, filled in the browser. /api/validate/ is NOT
    # taught to answer for it: an endpoint whose job is "this record
    # exists" must not have a mode where it says so about one that
    # does not.
    path("debug-sample/validate/", views.debug_sample_validate,
         name="debug_sample_validate"),

    # The card hand-off. The holder's own phone scans a QR on the document
    # page and saves the verification as a portrait image. NO SESSION: the
    # phone has no account here and cannot get one, so the token in the path
    # is the whole authorisation -- unguessable, five minutes, and released
    # when the operator leaves the document. It is the only endpoint that
    # serves an identity unauthenticated; read accounts.models.CardHandoff
    # before changing it. A token that is not a UUID does not match the route
    # at all, so a malformed one never reaches a query.
    path("card/<uuid:token>/", views.card_handoff, name="card_handoff"),
    # The same card in Apple Wallet: one pass, the offline credential as its
    # barcode and the holder's photo as its picture -- the pass idmanager
    # gives. Same token, same rules; drawn only when the deployment holds an
    # Apple Pass Type certificate. See accounts/wallet_pass.py.
    path("card/<uuid:token>/pass/", views.card_handoff_pass,
         name="card_handoff_pass"),
    path("card/<uuid:token>/release/", views.card_handoff_release,
         name="card_handoff_release"),

    # The phones a signed-in operator has paired. Session + CSRF; each action
    # is filtered by the signed-in user, so a device id belonging to somebody
    # else simply is not found.
    path("app/devices/", views.devices, name="devices"),
    path("app/devices/ticket/", views.devices_ticket, name="devices_ticket"),
    path("app/devices/rename/", views.devices_rename, name="devices_rename"),
    # Which organizations a phone works for: the context its app offers and
    # its log records name, never what it may read. The ticked boxes against
    # the organizations this person may enter, and nothing else.
    path("app/devices/organizations/", views.devices_organizations,
         name="devices_organizations"),
    path("app/devices/revoke/", views.devices_revoke, name="devices_revoke"),

    # The verifier app. No session and no CSRF: the caller is not a browser.
    # A scanned ticket is exchanged at /connect/ for where to talk, then spent
    # by the one operation it names; everything after is authenticated by a
    # signature from a key that never leaves the phone's Secure Enclave.
    path("api/v1/device/connect/", views.device_connect, name="device_connect"),
    path("api/v1/device/enrol/", views.device_enrol, name="device_enrol"),
    path("api/v1/device/challenge/", views.device_challenge,
         name="device_challenge"),
    path("api/v1/device/keys/", views.device_keys, name="device_keys"),
    # The device activity log. The key is public and issuer-signed, so it is
    # served to anyone; an upload is signed by the Enclave key over the
    # challenge AND the records, and opened here -- the phone holds no key
    # that reads its own log. See accounts/device_log.py.
    path("api/v1/device/log-key/", views.device_log_key,
         name="device_log_key"),
    path("api/v1/device/logs/", views.device_logs, name="device_logs"),
    # A person who verified THEMSELVES in idmanager registers their own phone
    # and is issued a credential. 404 unless an idmanager key is pinned. The
    # phone it registers is capped at the public tier, and the person it
    # creates cannot sign in here -- read accounts/holders.py first.
    path("api/v1/holder/register/", views.holder_register,
         name="holder_register"),
    # The holder's card as an Apple Wallet pass, for a phone registered
    # above. 404 unless a Pass Type certificate is configured too.
    path("api/v1/holder/passes/", views.holder_passes,
         name="holder_passes"),
    path("api/validate/<str:transaction_uuid>/", views.validate_transaction_api, name="validate_api"),
    # The verified answer is kept by /everify/ itself
    # (accounts/verified_answer.py); no route stores one the browser posts.

    # Organization administration. Every one of these resolves the
    # organization from the SESSION, never from the request, so an admin of
    # one organization cannot reach another by changing an id.
    path("app/admin/", views.organization_admin, name="app_admin"),
    path("app/admin/export-transactions/", views.admin_export_transactions, name="admin_export_transactions"),
    # What this organization's phones recorded while working for IT -- the
    # records filed under it at upload, never everything its members' phones
    # did. The site-wide export below is the one that sees every phone.
    path("app/admin/export-device-logs/", views.admin_export_device_logs, name="admin_export_device_logs"),
    path("app/admin/stats/", views.admin_stats, name="admin_stats"),
    path("app/admin/profile/", views.org_save_profile, name="org_save_profile"),
    path("app/admin/everify/", views.org_save_everify, name="org_save_everify"),
    path("app/admin/verification/", views.org_save_verification, name="org_save_verification"),
    path("app/admin/add-user/", views.org_add_member, name="admin_add_user"),
    path("app/admin/update-role/", views.org_update_member_role, name="admin_update_role"),
    path("app/admin/remove-user/", views.org_remove_member, name="admin_remove_user"),
    path("app/admin/add-location/", views.org_add_location, name="admin_add_location"),
    path("app/admin/update-location/", views.org_update_location, name="admin_update_location"),
    path("app/admin/remove-location/", views.org_remove_location, name="admin_remove_location"),
    path("app/admin/add-transaction-type/", views.org_add_transaction_type, name="admin_add_tt"),
    path("app/admin/update-transaction-type/", views.org_update_transaction_type, name="admin_update_tt"),
    path("app/admin/remove-transaction-type/", views.org_remove_transaction_type, name="admin_remove_tt"),

    # Site administration. Gated on User.is_site_admin, which is independent
    # of any membership -- otherwise nobody could create the first
    # organization.
    path("app/site/", views.site_admin, name="site_admin"),
    # A form, not a create: the row appears only when it is submitted.
    path("app/site/organizations/new/", views.site_new_organization, name="site_new_org"),
    path("app/site/organizations/<int:org_id>/", views.site_organization, name="site_organization"),
    path("app/site/organizations/<int:org_id>/members/", views.site_assign_member, name="site_assign_member"),
    path("app/site/organizations/<int:org_id>/members/remove/", views.site_remove_member, name="site_remove_member"),
    path("app/site/people/<int:user_id>/restricted-tier/", views.site_restricted_tier, name="site_restricted_tier"),
    path("app/site/organizations/<int:org_id>/toggle/", views.site_toggle_organization, name="site_toggle_org"),
    path("app/site/organizations/<int:org_id>/delete/", views.site_delete_organization, name="site_delete_org"),
    path("app/site/organizations/<int:org_id>/copy-credentials/", views.site_copy_credentials, name="site_copy_credentials"),
    path("app/site/organizations/<int:org_id>/fields/", views.site_save_fields, name="site_save_fields"),
    # Every phone's activity log, as CSV. A phone belongs to a person, and a
    # person may belong to several organizations, so the WHOLE log is
    # site-level; an organization's admin gets only the records filed under
    # that organization (export-device-logs above).
    path("app/site/device-logs/export/", views.site_export_device_logs, name="site_export_device_logs"),

    # The revocation feed a configured device polls. Unauthenticated and
    # SIGNED: this app has no device registry, and an API key would only mean
    # a stripped feed reads as "cannot connect" instead of "nothing revoked" --
    # both of which are what an attacker wants. The signature is the control.
    path("api/v1/revocations/", views.revocation_feed, name="revocation_feed"),

    # The credential signer's reconciler, over loopback, token only. nginx
    # answers 404 for this prefix from outside.
    path("api/v1/signer/report/", views.signer_report, name="signer_report"),
    # A signer that dials out (SIGNER_QUEUE_KEY): its long poll for jobs and
    # its answers, HMAC both ways, 404 without the key. A site in that mode
    # lets these through its proxy from the signer's address; this
    # repository's nginx keeps answering 404 for the whole prefix.
    path("api/v1/signer/jobs/", views.signer_jobs, name="signer_jobs"),
    path("api/v1/signer/answers/", views.signer_answers, name="signer_answers"),

    path("api/lookup-data/", views.get_lookup_data, name="lookup_data"),
    path("logout/", views.logout, name="logout"),
    path("decode-qr/", views.decode_national_id_qr, name="decode_national_id_qr"),
    # NOTE: no "qr-login/" route: nothing may sign in from the request body
    # without upstream verification -- see the comment in verify/views/qr.py.
    # Single sign-on. Only live while SiteSettings selects it AND the client
    # credentials are complete; both views bail to home() otherwise. The
    # callback path is the one registered on the provider.
    path("sso/login/", views.sso_login, name="sso_login"),
    path("national-id/callback/", views.sso_callback, name="sso_callback"),
    path("everify/", views.everify_query_api, name="everify_query"),
    path("everify/key/", views.everify_public_key, name="everify_key"),
    path("everify/log-liveness-failure/", views.log_liveness_failure, name="log_liveness_failure"),
    path("everify/log-transaction/", views.log_verification_transaction, name="log_transaction"),
    path("admin/", admin.site.urls),
]
