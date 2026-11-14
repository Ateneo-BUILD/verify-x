"""Views package. Re-exports all view functions so urls.py stays flat."""

from .core import (
    home, app, admin_export_transactions, admin_stats,
    get_lookup_data, validate, validate_transaction_api,
    document, logout, setup,
    revocation_feed, devices, devices_ticket, devices_rename,
    devices_organizations, devices_revoke, user_records_api,
)
from .orgs import (
    choose, switch, organization_admin,
    org_save_profile, org_save_everify, org_save_verification,
    org_add_member, org_update_member_role, org_remove_member,
    org_add_location, org_update_location, org_remove_location,
    org_add_transaction_type, org_update_transaction_type,
    org_remove_transaction_type,
    site_admin, site_new_organization, site_organization,
    site_assign_member, site_remove_member, site_toggle_organization,
    site_delete_organization, site_restricted_tier,
    site_copy_credentials, site_save_fields, site_export_device_logs,
    admin_export_device_logs,
)
from .device_api import (device_challenge, device_connect, device_enrol,
                         device_keys, device_log_key, device_logs)
from .holder_api import holder_passes, holder_register
from .signer_api import answers as signer_answers
from .signer_api import jobs as signer_jobs
from .signer_api import report as signer_report
from .signing import (signing_activate, signing_certificate, signing_csr,
                      signing_discard, signing_generate, signing_pause,
                      signing_publish, signing_request, signing_resume,
                      signing_suspend, signing_unsuspend, signing_withdraw)
from .debug import debug_cleanup, debug_sample, debug_sample_validate
from .handoff import card_handoff, card_handoff_pass, card_handoff_release
from .qr import decode_national_id_qr
from .sso import sso_login, sso_callback
from .everify import (everify_public_key, everify_query_api,
                      log_liveness_failure, log_verification_transaction)
