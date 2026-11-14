import logging

from django import forms
from django.contrib import admin
from django.contrib.admin import helpers as admin_helpers

from django.utils.html import format_html

from . import admin_roles, everify_address, org_names, restricted_tier
from .models import (Device, DeviceLogEntry, DeviceOrganization,
                     DeviceTicket, HolderAssertion,
                     IssuedCredential, IssuerKey, DebugCapture, Location,
                     LoginAttempt, Membership, Organization,
                     RevokedCredentialId, Transaction, TransactionType, User,
                     UserRecordsRead,
                     CARD_NUMBER, bridge_row)

logger = logging.getLogger(__name__)


class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 0
    autocomplete_fields = ("user",)


#: The two eVerify credentials an organization keeps that are never shown
#: back: (model field, form field to replace it, form field to clear it).
WRITE_ONLY_SECRETS = (
    ("everify_client_secret", "new_client_secret", "clear_client_secret"),
    ("everify_public_api_key", "new_public_api_key", "clear_public_api_key"),
)


class OrganizationAdminForm(forms.ModelForm):
    """The eVerify address meets the same rule here as on the Site page, and
    the two secrets are write-only here as they are there: never rendered
    back, kept when left blank, cleared only by the box that says so."""

    new_client_secret = forms.CharField(
        label="eVerify client secret", required=False, strip=True,
        widget=forms.PasswordInput(render_value=False,
                                   attrs={"autocomplete": "new-password"}),
        help_text="Write-only. Leave blank to keep the stored one.")
    clear_client_secret = forms.BooleanField(
        label="Clear the stored client secret", required=False)
    new_public_api_key = forms.CharField(
        label="eVerify public API key", required=False, strip=True,
        widget=forms.PasswordInput(render_value=False,
                                   attrs={"autocomplete": "new-password"}),
        help_text="Write-only. Leave blank to keep the stored one.")
    clear_public_api_key = forms.BooleanField(
        label="Clear the stored public API key", required=False)

    class Meta:
        model = Organization
        exclude = tuple(field for field, _, _ in WRITE_ONLY_SECRETS)

    def clean_name(self):
        """The rule the Site and Organization pages apply: one script, and
        no other organization's name in any spelling."""
        value = (self.cleaned_data.get("name") or "").strip()
        if self.instance.pk and value == self.instance.name:
            return value  # unchanged; not re-judged
        error = org_names.problem(value, self.instance)
        if error:
            raise forms.ValidationError(error)
        return value

    def clean_everify_base_url(self):
        value = self.cleaned_data.get("everify_base_url") or ""
        if self.instance.pk and value == self.instance.everify_base_url:
            return value  # stored before the rule; not re-judged
        url, error = everify_address.clean(value)
        if error:
            raise forms.ValidationError(error)
        return url

    def save(self, commit=True):
        org = super().save(commit=False)
        self.secrets_changed = []
        for field, new, clear in WRITE_ONLY_SECRETS:
            if self.cleaned_data.get(clear):
                setattr(org, field, "")
                self.secrets_changed.append(f"{field} cleared")
            elif self.cleaned_data.get(new):
                setattr(org, field, self.cleaned_data[new])
                self.secrets_changed.append(f"{field} replaced")
        if commit:
            org.save()
            self.save_m2m()
        return org


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    form = OrganizationAdminForm
    list_display = ("name", "is_active", "everify_configured", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name",)
    inlines = (MembershipInline,)
    fieldsets = (
        ("Identity", {"fields": ("name", "subtitle", "mark_color", "logo_data")}),
        ("eVerify client", {
            "description": "Used for verifications performed by this "
                           "organization. Operator sign-in uses the "
                           "site-level client on Site settings instead. "
                           "The secret and the public API key are never "
                           "shown back.",
            "fields": ("everify_base_url", "everify_client_id",
                       "secrets_stored",
                       "new_client_secret", "clear_client_secret",
                       "new_public_api_key", "clear_public_api_key"),
        }),
        ("Access", {"fields": ("is_active",)}),
    )
    readonly_fields = ("secrets_stored",)

    def get_readonly_fields(self, request, obj=None):
        # Whatever answers at this address decides who a verified person
        # is, so in Django admin as on the site's own pages only the people
        # who are site admins -- superusers -- change it.
        fields = list(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            fields.append("everify_base_url")
            # The name its documents say issued them: a superuser's once
            # it has verified anybody, as on the Organization page.
            if obj is not None and org_names.has_issued(obj):
                fields.append("name")
        return fields

    def has_delete_permission(self, request, obj=None):
        """Deleted from the Site page only: it refuses an organization with
        history or with a signing key phones list, and discards one never
        published. A delete here would skip both, so there is none."""
        return False

    @admin.display(boolean=True, description="eVerify configured")
    def everify_configured(self, obj):
        return obj.everify_configured

    @admin.display(description="Stored")
    def secrets_stored(self, obj):
        def state(value):
            return "set" if value else "not set"
        return (f"client secret {state(obj.everify_client_secret)}, "
                f"public API key {state(obj.everify_public_api_key)}")

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if change and "name" in form.changed_data:
            org_names.log_rename(f"django:{request.user.pk}", obj,
                                 form.initial.get("name"), obj.name)
        if "everify_base_url" in form.changed_data:
            everify_address.log_change(f"django:{request.user.pk}",
                                       f"organization {obj.pk}",
                                       form.initial.get("everify_base_url"),
                                       obj.everify_base_url)
        for what in getattr(form, "secrets_changed", ()):
            logger.warning("Organization %s: %s by django user %s in Django admin",
                           obj.pk, what, request.user.pk)


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role", "created_at")
    list_filter = ("role", "organization")
    search_fields = ("user__national_id_card_number", "user__digital_national_id",
                     "user__last_name", "user__given_name", "organization__name")
    autocomplete_fields = ("user", "organization")


class UserAdminForm(forms.ModelForm):
    """A card number typed here has the shape every typed one has: 16 digits.
    The bridge's ADMIN numbers are its own, so staff adding a row cannot
    plant the one a Django account would be bound to. A stored number that
    is not changed is not re-judged."""

    class Meta:
        model = User
        fields = "__all__"

    def clean_national_id_card_number(self):
        value = (self.cleaned_data.get("national_id_card_number") or "").strip()
        if self.instance.pk and value == self.instance.national_id_card_number:
            return value
        if not CARD_NUMBER.fullmatch(value):
            raise forms.ValidationError(
                "A National ID card number is 16 digits, without dashes.")
        return value

    def clean(self):
        data = super().clean()
        if data.get("is_site_admin") and data.get("is_all_org_admin"):
            raise forms.ValidationError(
                "A person is a site admin or an admin of every organization, "
                "not both. A site admin already administers every one.")
        return data


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    form = UserAdminForm
    list_display = ("national_id_card_number", "digital_national_id", "given_name",
                    "last_name", "is_site_admin", "is_all_org_admin",
                    "device_restricted_tier", "registered_via", "date_created")
    list_filter = ("is_site_admin", "is_all_org_admin", "device_restricted_tier",
                   "registered_via")
    search_fields = ("national_id_card_number", "digital_national_id", "last_name", "given_name")
    inlines = (MembershipInline,)
    fieldsets = (
        ("National ID", {"fields": ("national_id_card_number", "digital_national_id")}),
        ("Personal Info", {"fields": ("given_name", "middle_name", "last_name")}),
        ("Access", {
            "description": "Roles inside an organization are set by the "
                           "memberships below. These flags are site-wide. "
                           "A superuser may make a person a site admin or an "
                           "admin of every organization here, recorded as "
                           "their designation; a designated site admin may "
                           "do everything a site admin does except publish "
                           "or start an organization's signing key. A Django "
                           "account's own row (card number ADMIN...) is not "
                           "set here: it follows the account (a superuser is "
                           "a site admin, other staff admins of every "
                           "organization). "
                           "Device access is granted to the PERSON, not to a "
                           "handset: withdrawing it here reaches every phone "
                           "they have paired, at that phone's next sync.",
            "fields": ("is_site_admin", "is_all_org_admin", "admin_role_granted_by",
                       "admin_role_granted_at", "device_restricted_tier"),
        }),
        ("Dates", {"fields": ("date_created", "last_login")}),
        ("Origin", {
            "description": "\"idmanager\" is a holder who registered their own "
                           "phone after verifying themselves there. A holder "
                           "cannot sign in here until an organization adds "
                           "them as a member.",
            "fields": ("registered_via",),
        }),
    )
    readonly_fields = ("date_created", "last_login", "registered_via",
                       "admin_role_granted_by", "admin_role_granted_at")
    #: Site admin and admin of every organization: a superuser's to designate
    #: on a person's row (accounts/admin_roles.py), nobody's on a Django
    #: account's own row, whose role follows the account (bridge_roles).
    ROLES = ("is_site_admin", "is_all_org_admin")

    #: Who a row IS and what it may do. Reassigning a card number moves the
    #: next sign-in of that person onto this row, with its memberships and
    #: flags, so only a superuser changes these. The card number stays
    #: settable when a row is added; correcting one later is how a refused
    #: sign-in is fixed, by a superuser.
    IDENTITY = ("national_id_card_number", "digital_national_id")
    ACCESS = ("device_restricted_tier",)

    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            fields += list(self.ACCESS)
            if obj is not None:
                fields += list(self.IDENTITY)
        if not request.user.is_superuser or (obj is not None and obj.is_bridge_row):
            fields += list(self.ROLES)
        return fields

    def save_model(self, request, obj, form, change):
        """A change of the restricted tier here is a grant like any other:
        recorded with who made it, and logged."""
        if not change and not request.user.is_superuser:
            # The field was not theirs to set, so the model's default would
            # have granted it: a person added by staff starts without it.
            obj.device_restricted_tier = False
        tier_changed = "device_restricted_tier" in form.changed_data
        role_changed = any(f in form.changed_data for f in self.ROLES)
        changed = [f for f in self.IDENTITY if change and f in form.changed_data]
        super().save_model(request, obj, form, change)
        if role_changed:
            # Recorded as this superuser's designation, and logged.
            admin_roles.designate(obj, admin_roles.role_of(obj), bridge_row(request.user),
                                  f"django admin, django user {request.user.pk}")
        if changed:
            logger.warning("User %s: %s changed by django user %s in Django admin",
                           obj.pk, ", ".join(changed), request.user.pk)
        if tier_changed or (not change and obj.device_restricted_tier):
            actor = bridge_row(request.user)
            via = f"django admin, django user {request.user.pk}"
            if obj.device_restricted_tier:
                restricted_tier.grant(obj, actor, via)
            else:
                restricted_tier.withdraw(obj, actor, via)


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "is_active", "created_at")
    list_filter = ("is_active", "organization")
    search_fields = ("name",)


@admin.register(TransactionType)
class TransactionTypeAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "is_active", "shared_in_user_records",
                    "created_at")
    list_filter = ("is_active", "shared_in_user_records", "organization")
    search_fields = ("name",)


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    """The verification log. Read-only, like the device log: an audit trail
    an administrator can rewrite or trim row by row is not one. Every
    row is written by a verification or a failure."""

    list_display = ("transaction_id", "verification_timestamp", "organization",
                    "transaction_type", "authentication_result",
                    "national_id_card_number", "operator_location")
    list_filter = ("authentication_result", "organization", "acting_as_site_admin",
                   "acting_as_all_org_admin",
                   "transaction_type")
    search_fields = ("transaction_id", "national_id_card_number", "digital_national_id_number",
                     "given_name", "last_name", "operator_location")
    readonly_fields = ("transaction_id", "verification_timestamp")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(UserRecordsRead)
class UserRecordsReadAdmin(admin.ModelAdmin):
    """Every look at a person's User Records. Read-only, as the transaction
    log is: a trace an administrator can trim is not one. The person is a
    keyed hash; search by it to see who else read the same history."""

    list_display = ("read_at", "operator", "organization", "records", "subject_key")
    list_filter = ("organization",)
    search_fields = ("subject_key",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """Sign-in attempts that were refused before eVerify was called.

    Read-only on purpose: it is an audit trail, and it holds faces. Deleting
    is left available so an admin can age rows out by hand.
    """

    list_display = ("created_at", "submitted_id", "id_kind", "has_photo",
                    "ip_address")
    list_filter = ("id_kind", "created_at")
    search_fields = ("submitted_id", "ip_address", "user_agent")
    readonly_fields = ("created_at", "submitted_id", "id_kind", "ip_address",
                       "user_agent", "photo_preview")
    exclude = ("photo_data",)
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.display(boolean=True, description="Photo")
    def has_photo(self, obj):
        return obj.has_photo

    @admin.display(description="Captured face")
    def photo_preview(self, obj):
        if not obj.photo_data:
            return "No capture -- the attempt did not come from the login page."
        # photo_data is validated by login_guard.clean_photo() before it is
        # stored: a real image data URI of a permitted type, or "".
        return format_html('<img src="{}" style="max-width:320px;">',
                           obj.photo_data)


@admin.register(IssuedCredential)
class IssuedCredentialAdmin(admin.ModelAdmin):
    """Every offline credential this deployment has minted.

    This table is the authoritative record, and revoking here is what puts a
    credential into the signed feed configured devices poll. There is no
    un-revoke: a credential withdrawn from circulation and then quietly
    restored is worse than one that was never withdrawn, and the device that
    already cached the revocation would disagree with the one that had not.

    Rows are not editable and not addable by hand -- one that exists here but
    not in the world means nothing, and one in the world but not here cannot
    be revoked at all, so both are only ever created by minting.
    """

    list_display = ("credential_id", "organization", "issued_at",
                    "expires_at", "is_revoked")
    list_filter = ("organization", "revoked_at", "epoch")
    search_fields = ("credential_id", "document_uuid")
    date_hierarchy = "issued_at"
    readonly_fields = ("credential_id", "transaction", "organization",
                       "document_uuid", "epoch", "issuer_key_id", "issued_at",
                       "expires_at", "revoked_at", "revoked_by",
                       "revoked_reason")
    actions = ("revoke_selected",)

    @admin.display(boolean=True, description="Revoked")
    def is_revoked(self, obj):
        return obj.revoked_at is not None

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        # A deleted row is a credential that can no longer be revoked, and a
        # deleted REVOKED row would quietly un-revoke it in every new feed.
        return False

    #: The most one action revokes. Revocation cannot be undone, and a
    #: select-all on this list is every document the site has issued.
    REVOKE_CAP = 100

    def _siblings(self, pending, limit):
        """Credentials not selected and not revoked that the same operator
        issued about the same person, at the same organization, within one
        sign-in of a selected one: what one kept answer can print more of.
        Shown on the confirmation, so whoever revokes one sees the spares and
        can revoke them too."""
        from datetime import timedelta

        from django.conf import settings
        from django.db.models import Q

        window = timedelta(seconds=settings.SESSION_ABSOLUTE_SECONDS)
        near = Q()
        for credential in pending.select_related("transaction"):
            txn = credential.transaction
            if txn is None or not txn.subject_key:
                continue
            near |= Q(transaction__subject_key=txn.subject_key,
                      transaction__operator_id=txn.operator_id,
                      organization_id=credential.organization_id,
                      transaction__verification_timestamp__range=(
                          txn.verification_timestamp - window,
                          txn.verification_timestamp + window))
        if not near.children or limit <= 0:
            return []
        return list(IssuedCredential.objects.filter(near, revoked_at__isnull=True)
                    .exclude(pk__in=pending.values("pk")).order_by("pk")[:limit])

    def has_revoke_permission(self, request):
        """Revoking needs the change permission on issued credentials, which
        view-only staff do not hold, although the page itself never changes
        a row."""
        return request.user.has_perm("accounts.change_issuedcredential")

    @admin.action(description="Revoke the selected credentials",
                  permissions=["revoke"])
    def revoke_selected(self, request, queryset):
        """Asks first, says how many, takes a reason, and records who."""
        from django.contrib import messages
        from django.template.response import TemplateResponse

        from accounts import revocation_feed

        pending = queryset.filter(revoked_at__isnull=True)
        count = pending.count()
        if count == 0:
            self.message_user(request, "Every selected credential is already "
                              "revoked.", messages.WARNING)
            return None
        if count > self.REVOKE_CAP:
            self.message_user(
                request, "%d not yet revoked are selected. Revoke at most %d "
                "at a time: revocation cannot be undone." % (count, self.REVOKE_CAP),
                messages.ERROR)
            return None
        siblings = self._siblings(pending, self.REVOKE_CAP - count)
        ticked = set(request.POST.getlist("also"))
        also = [c for c in siblings if str(c.pk) in ticked]
        reason = (request.POST.get("reason") or "").strip()
        answered = request.POST.get("post") == "yes"
        # The page posts back exactly the credentials it listed, never "all
        # of the filter": one issued while the reason was being typed is not
        # revoked unseen. If what is pending is no longer what was shown, it
        # asks again.
        changed = answered and request.POST.get("shown") != str(count)
        if not answered or not reason or changed:
            return TemplateResponse(
                request, "admin/accounts/issuedcredential/revoke_confirmation.html",
                {**self.admin_site.each_context(request),
                 "title": "Revoke credentials",
                 "opts": self.model._meta,
                 "credentials": list(pending.order_by("pk")),
                 "siblings": siblings,
                 "ticked": {str(c.pk) for c in also},
                 "count": count,
                 "reason": reason,
                 "reason_missing": answered and not reason and not changed,
                 "changed": changed,
                 "action_checkbox_name": admin_helpers.ACTION_CHECKBOX_NAME})
        actor = bridge_row(request.user)
        reason = "Django admin: " + reason
        count += len(also)
        for credential in list(pending) + also:
            revocation_feed.revoke(credential, actor=actor, reason=reason)
            self.log_change(request, credential, "Revoked. " + reason)
            logger.warning("Credential %s revoked in Django admin by django user "
                           "%s: %s", credential.credential_id, request.user.pk,
                           reason)
        self.message_user(
            request,
            "%d credential%s revoked. Devices pick this up the next time they "
            "poll the revocation feed." % (count, "" if count == 1 else "s"))
        return None


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    """Phones paired to an account.

    Read-only. A device row is created by an enrolment that spent a one-time
    code and presented a Secure Enclave public key; editing one by hand could
    only make it describe a phone that does not exist. Revoking is the action,
    and it belongs to the owner as well as here.

    Note the tier column is the OWNER's, read live -- change it on the person,
    not here.
    """

    list_display = ("label", "owner", "restricted_tier", "public_tier_only",
                    "is_active", "last_sync_at", "enrolled_at")
    list_filter = ("revoked_at", "enrolled_at", "public_tier_only")
    search_fields = ("label", "device_id", "owner__national_id_card_number")
    readonly_fields = ("device_id", "label", "owner", "public_key_der",
                       "attest_key_id", "attest_counter", "attest_status",
                       "attest_detail", "attest_checked_at", "enrolled_at",
                       "last_sync_at", "lease_expires_at", "revoked_at",
                       "revoked_by", "revoked_reason", "public_tier_only")
    actions = ("revoke_selected",)

    @admin.display(boolean=True, description="Reads holder details")
    def restricted_tier(self, obj):
        return obj.restricted_tier

    @admin.display(boolean=True, description="Active")
    def is_active(self, obj):
        return obj.is_active

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.action(description="Revoke the selected devices", permissions=["change"])
    def revoke_selected(self, request, queryset):
        from accounts import devices as device_service

        done = 0
        for device in queryset.filter(revoked_at__isnull=True):
            device_service.revoke(device, reason="Revoked from the Django admin")
            done += 1
        self.message_user(
            request, "%d device%s revoked. They stop receiving keys; the ones "
                     "they already hold expire with their lease."
                     % (done, "" if done == 1 else "s"))


@admin.register(DeviceTicket)
class DeviceTicketAdmin(admin.ModelAdmin):
    """One-time codes handing an operation to a phone. Read-only by design.

    Read-only rather than merely awkward to edit: a ticket that could be
    created here would be one authorising an operation nobody signed in to
    ask for, and one whose purpose could be edited would be a sync ticket
    turned into an enrolment.
    """

    list_display = ("code", "purpose", "user", "device", "created_at",
                    "expires_at", "used_at")
    list_filter = ("purpose", "used_at", "created_at")
    search_fields = ("code", "user__national_id_card_number")
    readonly_fields = ("code", "purpose", "user", "label", "created_at",
                       "expires_at", "used_at", "device", "organizations")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(DeviceOrganization)
class DeviceOrganizationAdmin(admin.ModelAdmin):
    """Which organizations each phone works for, and has worked for.

    Read-only. A link is changed by the phone's owner on the Devices page,
    where the rule about which organizations they may pick is applied. An
    ended link is history the device log is attributed by, so do not delete
    one by hand: records the phone wrote for that organization and has not
    sent yet would arrive filed under none. Delete permission is left at the
    default only because a phone, an organization or a person deleted here
    cascades to these rows, and refusing it would refuse those deletes too.
    """

    list_display = ("device", "organization", "linked_at", "linked_by",
                    "unlinked_at", "unlinked_by")
    list_filter = ("organization", "unlinked_at")
    search_fields = ("device__label", "device__device_id",
                     "organization__name")
    readonly_fields = ("device", "organization", "linked_at", "linked_by",
                       "unlinked_at", "unlinked_by")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(HolderAssertion)
class HolderAssertionAdmin(admin.ModelAdmin):
    """The idmanager assertions this deployment accepted. Read-only.

    The record of whose phone was registered on idmanager's word, and on the
    strength of a check made when. A row exists only because an assertion was
    spent; one added or edited by hand would be a registration nobody made.
    Revoke the DEVICE, or the credential, to undo one.
    """

    list_display = ("accepted_at", "user", "device", "issuer", "key_id",
                    "verified_at")
    list_filter = ("issuer", "key_id", "accepted_at")
    search_fields = ("jti", "subject", "user__national_id_card_number")
    readonly_fields = ("jti", "issuer", "key_id", "subject", "user", "device",
                       "verified_at", "expires_at", "accepted_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(IssuerKey)
class IssuerKeyAdmin(admin.ModelAdmin):
    """The keys devices are told to trust.

    Written by `manage.py load_credential_keys` from the verifier fleet's own
    registration, so the two cannot disagree about which key is which. Editing
    one here would be how this deployment ends up naming a key nobody trusts.
    """

    list_display = ("key_id", "source", "state", "certified_name", "is_active",
                    "not_before", "not_after")

    # Fully read-only. With a signer this is a mirror of its registry, and
    # without one `load_credential_keys` writes it; either way an edit here
    # is how a deployment ends up naming a key nobody trusts.
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(RevokedCredentialId)
class RevokedCredentialIdAdmin(admin.ModelAdmin):
    """Credential ids revoked without having been issued here: forgeries.

    Add only. There is no un-revoke, and a row deleted here would drop a
    forgery back out of every phone's filter.
    """

    list_display = ("credential_id", "reason", "added_by", "added_at")
    search_fields = ("credential_id",)
    fields = ("credential_id", "reason")

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        from accounts import revocation_feed

        # Who added it, as the row's own column says.
        django_user = getattr(request, "user", None)
        revocation_feed.add_forged([obj.credential_id], reason=obj.reason,
                                   actor=bridge_row(django_user))
        logger.warning("Forged credential id %s revoked in Django admin by "
                       "django user %s: %s", obj.credential_id,
                       getattr(django_user, "pk", None), obj.reason)
        # Re-read so the admin's success message names the stored row.
        obj.pk = RevokedCredentialId.objects.get(
            credential_id=obj.credential_id).pk


@admin.register(DebugCapture)
class DebugCaptureAdmin(admin.ModelAdmin):
    """Whole eVerify responses kept on a development instance.

    Read-only and un-addable for the same reason LoginAttempt is: a row
    describes what an upstream actually returned, and one typed by hand would
    describe a lookup that never happened -- which is worse than no data at
    all for anything measured off this table.

    Deleting is left available, and `manage.py debug_cleanup` empties it in
    one go. This table holds faces; treat it as sensitive.
    """

    list_display = ("created_at", "purpose", "outcome", "status_code",
                    "detail", "organization", "field_count", "has_photo")
    list_filter = ("purpose", "outcome", "created_at")
    readonly_fields = ("created_at", "purpose", "outcome", "status_code",
                       "detail", "organization", "payload",
                       "photo_preview")
    exclude = ("photo_data",)
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.display(description="Face")
    def photo_preview(self, obj):
        if not obj.photo_data:
            return "(none)"
        return format_html(
            '<img src="{}" style="max-height:180px;border-radius:4px">',
            obj.photo_data)


@admin.register(DeviceLogEntry)
class DeviceLogEntryAdmin(admin.ModelAdmin):
    """The phones' activity log, opened. Read-only, and not deletable here.

    Every row came from a phone's sealed, signed upload; one added or edited
    by hand would be a record of something no phone did, in the one table
    whose job is to say what phones did. Deleting is withheld for the same
    reason -- an audit trail an administrator can trim row by row is not one.
    Retention is `manage.py purge_device_logs`, by age, all rows alike,
    run daily by the timer every deploy installs.

    The export on the site admin page is the way to read it in bulk.
    `DeviceLogKey` is deliberately not registered: it holds a wrapped
    private key and there is nothing about it to look at.
    """

    list_display = ("received_at", "device_label", "owner_name", "seq",
                    "event", "outcome", "organization_name", "occurred_at",
                    "chain_ok", "readable")
    list_filter = ("event", "outcome", "chain_ok", "readable")
    search_fields = ("device_uuid", "device_label", "owner_name",
                     "owner_national_id_number", "event",
                     "organization_name")
    readonly_fields = ("device", "device_uuid", "device_label", "owner",
                       "owner_name", "owner_national_id_number", "seq",
                       "key_id", "event", "outcome", "detail", "app_build",
                       "occurred_at", "received_at", "record_hash_hex",
                       "chain_ok", "readable", "organization",
                       "organization_name", "claimed_organization_id")
    exclude = ("record_hash",)
    date_hierarchy = "received_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="Record hash")
    def record_hash_hex(self, obj):
        return bytes(obj.record_hash or b"").hex()
