import re
import uuid

from django.db import models
from django.utils.timezone import now as timezone_now


class Organization(models.Model):
    """A tenant: its own operators, locations, transaction types and eVerify client.

    The eVerify credentials here are the ones VERIFICATIONS run against, so
    they are what a organization's usage is billed to. They deliberately do
    NOT sign anybody in -- at the login page there is no organization yet,
    so operator sign-in uses the site-level credentials on SiteSettings.

    There is no fallback to the site credentials: an organization with no
    client of its own cannot verify, and says so. A fallback would silently
    bill one organization's verifications to another's client.
    """

    name = models.CharField(max_length=255, unique=True)
    subtitle = models.CharField(max_length=255, blank=True, default="")

    #: Short code naming this organization inside an offline credential.
    #: Stored rather than derived from `name`, for two reasons that both bite:
    #: a credential is signed and outlives a rename, so a derived code would
    #: make old and new credentials disagree about who issued them; and
    #: initials collide -- "Philippine Statistics Authority" and a "Public
    #: Service Agency" both reduce to PSA. Uppercase A-Z0-9 only, because the
    #: whole QR string has to stay inside the alphanumeric charset.
    issuer_code = models.CharField(max_length=8, unique=True, null=True,
                                   blank=True, default=None)

    #: Names this organization to the credential signer, and in the
    #: `organizationIdentifier` of its signing certificate when it has one.
    #: A UUID rather than
    #: the primary key or the name: a certificate outlives a rename and must
    #: never come to name a different organization, so this is never reused.
    signing_id = models.UUIDField(default=uuid.uuid4, unique=True,
                                  editable=False)

    #: A complete `data:image/...;base64,...` URI, or "". Stored in the row
    #: rather than as a file: deploy/deploy.sh rsyncs the app to instances
    #: with no shared media volume, so an uploaded file would exist on one
    #: instance only. In the row it also rides the off-site database backups.
    logo_data = models.TextField(blank=True, default="")
    #: Background for the initials mark shown when no logo is uploaded.
    mark_color = models.CharField(max_length=7, blank=True, default="#00386a")

    # --- Where it is, and who to ask about it ---------------------------
    # An organization is a real place with somebody answerable for it, and
    # neither fact was recorded anywhere. Every one of these is OPTIONAL and
    # must stay that way: deployments already have organizations, and a
    # required address would stop an admin saving an unrelated change until
    # they went and found one.
    address_line1 = models.CharField(max_length=255, blank=True, default="")
    address_line2 = models.CharField(max_length=255, blank=True, default="")
    barangay = models.CharField(max_length=120, blank=True, default="")
    municipality = models.CharField(max_length=120, blank=True, default="")
    postal_code = models.CharField(max_length=16, blank=True, default="")
    country = models.CharField(max_length=120, blank=True, default="")

    #: A named human being and their details -- the first personal data this
    #: page has ever held, so all three are masked under Demo Mode and are
    #: guarded by is_demo_masked() on save. mask_name keeps the first word of
    #: a person's name; mask_identifier keeps the last character of an
    #: address or a number.
    contact_person = models.CharField(max_length=255, blank=True, default="")
    contact_email = models.EmailField(max_length=254, blank=True, default="")
    contact_mobile = models.CharField(max_length=32, blank=True, default="")

    everify_base_url = models.CharField(
        max_length=255, blank=True, default="https://ws.everify.gov.ph/api")
    everify_client_id = models.CharField(max_length=255, blank=True, default="")
    everify_client_secret = models.CharField(max_length=255, blank=True, default="")
    everify_public_api_key = models.TextField(blank=True, default="")

    is_active = models.BooleanField(default=True)

    #: User Records: after a successful verification, show this
    #: organization's operators the person's earlier transactions from EVERY
    #: organization (accounts/user_records.py). On by default, existing
    #: organizations included. A SITE ADMIN's switch: it opens every
    #: organization's records to this one's operators, so it is not the
    #: tenant's own to turn on. It governs what
    #: its operators see, not whether its own records appear to others --
    #: they do, less the types it keeps to itself
    #: (TransactionType.shared_in_user_records).
    check_user_records = models.BooleanField(default=True)

    #: Repeat alert, part of User Records: when the transaction type an
    #: operator picks was already logged for the same person HERE, within
    #: the last `repeat_alert_days` (0 means any time), the document page
    #: warns beside Log Transaction. It informs and never blocks. Records of
    #: the same type from other organizations are marked either way; only
    #: this organization's raise the warning. On, 90 days, by default.
    repeat_alert = models.BooleanField(default=True)
    repeat_alert_days = models.PositiveIntegerField(default=90)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "organizations"
        ordering = ["name"]

    def __str__(self):
        return self.name

    @property
    def everify_configured(self):
        """Enough to run a verification against this organization's client."""
        return bool(self.everify_base_url and self.everify_client_id
                    and self.everify_client_secret)

    @property
    def initials(self):
        """Up to three letters for the fallback mark, from the name's words."""
        words = [w for w in self.name.replace("-", " ").split() if w[:1].isalnum()]
        if not words:
            return "?"
        if len(words) == 1:
            return words[0][:3].upper()
        return "".join(w[0] for w in words[:3]).upper()


def next_location_code(organization, name, exclude_pk=None):
    """A short, unique-within-its-organization code suggested from a name.

    Six characters, because that is what the QR budget allows once the rest of
    a credential is in it. Unique only within the organization: two
    organizations will both want a "Main Office", exactly as they both want
    the name.
    """
    import re as _re

    words = [w for w in name.replace("-", " ").split() if w[:1].isalnum()]
    if not words:
        base = "LOC"
    elif len(words) == 1:
        base = words[0][:6].upper()
    else:
        base = "".join(w[0] for w in words[:6]).upper()
    base = _re.sub(r"[^A-Z0-9]", "", base)[:6] or "LOC"

    used = Location.objects.filter(organization=organization).exclude(code="")
    if exclude_pk is not None:
        used = used.exclude(pk=exclude_pk)
    taken = set(used.values_list("code", flat=True))

    code, suffix = base, 2
    while code in taken:
        code = "%s%d" % (base[:6 - len(str(suffix))], suffix)
        suffix += 1
    return code


def next_issuer_code(name, taken=None):
    """A short, unique issuer code suggested from an organization's name.

    Only a suggestion, and only at creation: once stored it is never
    re-derived. Initials collide, so this checks what is already in use --
    the second PSA becomes PSA2.
    """
    import re as _re

    words = [w for w in name.replace("-", " ").split() if w[:1].isalnum()]
    if not words:
        base = "ORG"
    elif len(words) == 1:
        base = words[0][:3].upper()
    else:
        base = "".join(w[0] for w in words[:3]).upper()
    base = _re.sub(r"[^A-Z0-9]", "", base)[:8] or "ORG"

    if taken is None:
        taken = set(Organization.objects.exclude(issuer_code=None)
                    .values_list("issuer_code", flat=True))
    code, suffix = base, 2
    while code in taken:
        code = "%s%d" % (base[:8 - len(str(suffix))], suffix)
        suffix += 1
    return code


#: How the card number of a Django-admin bridge row starts: ADMIN and the
#: Django id, eleven digits. Typed card numbers are sixteen digits, so only
#: the bridge writes these (verify/views/helpers.py, _get_session_user).
BRIDGE_PREFIX = "ADMIN"


#: A National ID card number as typed: 16 digits once the dashes and spaces it
#: is printed with are gone. ASCII digits: \d would also take fullwidth ones.
#: Every card number a person types must have this shape, which is what keeps
#: the bridge's ADMIN card numbers its own.
CARD_NUMBER = re.compile(r"[0-9]{16}")
#: A Digital National ID as sign-in reads it: letters and digits only.
DIGITAL_ID = re.compile(r"[A-Z0-9]{1,20}")


def bridge_card(django_user_id):
    """The card number of the bridge row for a Django account."""
    return f"{BRIDGE_PREFIX}{django_user_id:011d}"


def bridge_row(django_user):
    """The User row standing for a Django account, for a record of who did
    something in Django admin: its bridge row, or None if it has never
    opened the site's own pages."""
    if django_user is None or not getattr(django_user, "pk", None):
        return None
    return User.objects.filter(
        national_id_card_number=bridge_card(django_user.pk)).first()


def bridge_roles(django_user):
    """(is_site_admin, is_all_org_admin) for a Django account's bridge row.

    The site-admin model: a Django superuser is a site administrator; a
    Django staff account that is not a superuser administers every
    organization and nothing site-wide; anything else, or an account that is
    gone or inactive, is neither. For a bridge row both flags are derived
    from the Django account here and written only by the bridge
    (verify/views/helpers.py) and accounts/django_bridge.py.

    Any other row -- an eVerify sign-in -- holds one only by a superuser's
    recorded designation (accounts/admin_roles.py). Such a site admin has
    every site power but one: publishing or starting an organization's
    signing key still takes a superuser's own login
    (User.switches_signing_keys).
    """
    if django_user is None or not django_user.is_active:
        return False, False
    if django_user.is_superuser:
        return True, False
    return False, bool(django_user.is_staff)


class User(models.Model):
    national_id_card_number = models.CharField(max_length=16, unique=True)
    digital_national_id = models.CharField(max_length=20, blank=True, default="")
    last_name = models.CharField(max_length=150, blank=True, default="")
    given_name = models.CharField(max_length=255, blank=True, default="")
    middle_name = models.CharField(max_length=150, blank=True, default="")
    #: Site-wide capability, independent of any membership: create and
    #: configure organizations. Site admins may also verify inside any
    #: organization; those transactions are stamped acting_as_site_admin so
    #: an organization's log never shows an operator it never assigned.
    #:
    #: The bridge row of an active Django superuser (bridge_roles), or a row
    #: a superuser designated (admin_roles; admin_role_granted_*). Nothing
    #: else sets it. 0046 cleared it from every row that was neither.
    is_site_admin = models.BooleanField(default=False)
    #: Admin of every organization, with no site-wide power: the bridge row of
    #: an active Django staff account that is not a superuser (bridge_roles),
    #: or a row a superuser designated (admin_roles). Enters every active
    #: organization as its admin, as a site admin does, and its transactions
    #: there are stamped acting_as_all_org_admin.
    is_all_org_admin = models.BooleanField(default=False)
    #: Who designated this row a site admin or admin of every organization,
    #: and when (accounts/admin_roles.py). Empty on a bridge row, whose role
    #: follows its Django account, and when neither role is held.
    admin_role_granted_by = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="+")
    admin_role_granted_at = models.DateTimeField(null=True, blank=True)

    #: May this person's phones decrypt the restricted tier of a credential --
    #: the holder's name, birth date and ID numbers -- rather than only
    #: confirming the document is genuine?
    #:
    #: On the PERSON, deliberately, not on the device. A self-service Devices
    #: page where somebody grants their own phone access would not be a
    #: control at all; and holding it here means withdrawing it reaches every
    #: phone they own at that phone's next sync, rather than requiring each
    #: handset to be found and edited.
    #:
    #: DEFAULT ON. These phones belong to an organization's own operators,
    #: checking a document against the person holding it -- and a verifier
    #: that cannot show the name it has just validated cannot make that
    #: comparison at all. Somebody trusted to run the verification on the
    #: web reads the same fields there. Still a per-person switch, and
    #: withdrawing it reaches every phone they own at its next sync.
    #:
    #: EXCEPT for a person an organization admin adds. Epoch keys are
    #: site-wide, so a phone that reads the restricted tier reads it for
    #: EVERY organization's documents, and an admin of one organization is
    #: not somebody who may hand that out. `org_add_member` creates the row
    #: with this off; a site administrator grants it on the Site organization
    #: page (or a superuser in Django admin), and the grant is recorded
    #: below. People a site administrator adds start with it on, and that
    #: add is recorded as the grant.
    device_restricted_tier = models.BooleanField(default=True)
    #: Who last granted the restricted tier, and when. Empty for a grant made
    #: before grants were recorded (0030's backfill, or an add before 0044),
    #: and cleared when it is withdrawn.
    restricted_tier_granted_by = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="+")
    restricted_tier_granted_at = models.DateTimeField(null=True, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)

    #: How this row came to exist, when it was not an organization adding an
    #: operator. "idmanager" is a HOLDER: somebody who verified themselves in
    #: idmanager and registered their own phone -- see accounts/holders.py.
    #:
    #: A holder is not an operator, and two rules keep it that way. Such a row
    #: cannot sign in to this site (`is_holder_only`, read by `_find_user()`
    #: and `registered_operator()`) until an organization makes them a member;
    #: and it is created with `device_restricted_tier` OFF, because the field
    #: default is on for operators and a member of the public must never be
    #: handed the key to every holder's details.
    REGISTERED_VIA_IDMANAGER = "idmanager"
    registered_via = models.CharField(max_length=16, blank=True, default="")

    @property
    def reaches_every_organization(self):
        """May enter every active organization, as its admin: a site admin
        or an admin of every organization."""
        return bool(self.is_site_admin or self.is_all_org_admin)

    @property
    def is_bridge_row(self):
        """A Django account's own row (bridge_card), whose roles follow it."""
        return self.national_id_card_number.startswith(BRIDGE_PREFIX)

    @property
    def switches_signing_keys(self):
        """May publish or start an organization's signing key: a site admin
        through a Django superuser's own login, and no designated one --
        putting a new certified name on every phone stays a superuser's
        act, even for a designated site admin."""
        return bool(self.is_site_admin and self.is_bridge_row)

    def may_switch_signing_keys(self, site_controls_all_keys=False):
        """May publish, start, withdraw, unsuspend and resume signing keys from
        the site's pages. `switches_signing_keys` -- unless the signer's own
        policy sets `site_controls_all_keys`, which it says in `public()` and
        nothing here can set: then any site admin, a designated one included.
        The decision, for a site whose app servers are replaced at every
        release; off holds as before."""
        return bool(self.switches_signing_keys
                    or (site_controls_all_keys and self.is_site_admin))

    @property
    def is_holder_only(self):
        """A holder nobody has made an operator. Signs in to nothing here.

        Membership or the site-admin flag is what turns a holder into somebody
        this site lets in -- an organization adding them is the same act that
        makes anybody an operator, so there is no second path to curate.
        """
        return (self.registered_via == self.REGISTERED_VIA_IDMANAGER
                and not self.reaches_every_organization
                and not self.memberships.exists())

    def save(self, *args, **kwargs):
        # Always store national ID as plain 16 digits (no dashes)
        if self.national_id_card_number:
            self.national_id_card_number = self.national_id_card_number.replace("-", "").replace(" ", "")
        super().save(*args, **kwargs)

    @property
    def national_id_formatted(self):
        """Display national ID with dashes: 1234-5678-9012-3456"""
        raw = self.national_id_card_number
        if raw and len(raw) == 16 and raw.isdigit():
            return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"
        return raw

    class Meta:
        db_table = "Users"

    @property
    def full_name(self):
        return f"{self.given_name} {self.last_name}".strip()

    @property
    def short_name(self):
        """The corner name: one given word and the WHOLE surname.

        The nav corner is a badge saying whose session this is, not a record
        of who somebody is -- full_name and display_name are still what the
        document footer, the member lists and a minted credential carry. So
        it takes only the first word of the given name; a multi-word given
        name is the ordinary case here (MARIA CLARA, JUAN PAULO) and is what
        made the corner long.

        The surname is never cut. DELA CRUZ, DE LOS SANTOS and SANTOS-LOPEZ
        are ONE surname each, and keeping only their last word would put a
        different -- and common -- surname in the corner: somebody else's.

        The one exception is the first word being an initial or an
        abbreviation, which names nobody: MA. CRISTINA would otherwise show
        as "MA.". So a first word shorter than SHORT_GIVEN_WORD gives way to
        the next word that is long enough.

        Length is counted in letters and digits, not characters, or "MA."
        would measure three and keep the very case this exists for. The word
        is still rendered as it is stored -- measuring is not rewriting.

        Masked as one string by mask_name(), like every other name in this
        app: the trim runs first and keeps the first word, so what Demo Mode
        has left to keep is unchanged by any of this.
        """
        return " ".join(part for part in (self._given_word(), self.last_name)
                        if part)

    #: Below this many letters a given word is an initial or an abbreviation
    #: -- "MA.", "T." -- and names nobody, so short_name looks past it.
    SHORT_GIVEN_WORD = 3

    def _given_word(self):
        words = self.given_name.split()
        if not words:
            return ""
        for word in words:
            if len(_letters(word)) >= self.SHORT_GIVEN_WORD:
                return word
        # Every word is short: an initial is still better than nothing, and
        # this is the one place the first word is kept whatever its length.
        return words[0]

    @property
    def display_name(self):
        """Given, middle and last as ONE string, for the admin pages.

        One string on purpose: Demo Mode redacts a name by keeping its first
        word and masking the rest, so three separately-masked single-word
        fields would each keep their whole word and redact nothing at all.
        """
        return " ".join(part for part in (self.given_name, self.middle_name,
                                          self.last_name) if part)

    @property
    def public_name(self):
        """What a credential, a pairing code and `/connect/` call this
        person: their name, or "Operator <id>" when none is on file.

        Never an ID number. A member an organization admin added by card
        number alone has no name until eVerify or SSO gives one, and a card
        number in its place would be signed into the public tier of every
        credential they issued, which every paired phone reads, and printed
        in their pairing codes. The row id names nobody outside this site's
        database."""
        return self.display_name or "Operator %d" % self.pk

    def memberships_in_active_orgs(self):
        return (self.memberships.select_related("organization")
                .filter(organization__is_active=True)
                .order_by("organization__name"))

    def __str__(self):
        return f"{self.given_name} {self.last_name} ({self.national_id_card_number})"


def _letters(word):
    """The part of a word that is name, not punctuation."""
    return "".join(ch for ch in word if ch.isalnum())


class Membership(models.Model):
    """A person's role inside one organization.

    Role lives here, not on User: the same person is routinely an admin at one
    organization and an operator at another, which a single column on the user
    cannot express.
    """

    ROLE_OPERATOR = "operator"
    ROLE_ADMIN = "admin"
    ROLE_CHOICES = [
        (ROLE_OPERATOR, "Operator"),
        (ROLE_ADMIN, "Admin"),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE,
                                     related_name="memberships")
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name="memberships")
    role = models.CharField(max_length=20, choices=ROLE_CHOICES,
                            default=ROLE_OPERATOR)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "memberships"
        unique_together = [("organization", "user")]
        ordering = ["organization__name", "user__last_name"]

    def __str__(self):
        return f"{self.user} @ {self.organization} ({self.role})"

    @property
    def is_admin(self):
        return self.role == self.ROLE_ADMIN


def organizations_open_to(user):
    """Active organizations this person may act for, by name.

    THE "may enter" rule, kept here so the pages and the device API read one
    copy of it: a site admin, or an admin of every organization, may enter
    every active organization; anybody else, an active organization they
    are a member of. The context chooser
    (`verify.views.helpers._available_organizations`) and what a phone is
    told it works for (`accounts.devices.organizations_for`) both call this
    -- were they two copies, a membership removed on one side would still
    open the other.
    """
    if user is None:
        return Organization.objects.none()
    if user.reaches_every_organization:
        return Organization.objects.filter(is_active=True).order_by("name")
    return Organization.objects.filter(
        is_active=True, memberships__user=user).order_by("name")


class FingerprintSettings(models.Model):
    """One operator's fingerprint reader, at one organization.

    Per (user, organization) rather than per user: the reader is a device on
    the workstation the operator is sitting at, so somebody who works at two
    organizations has two of them, on different endpoints and with different
    serial numbers. A single row per user would have them overwrite each
    other every time they switched.

    Absent means "no reader here", which is the common case -- the Verify page
    only offers the fingerprint button when a serial number is set.
    """

    DEFAULT_ENDPOINT = "http://127.0.0.1:4501/capture"

    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name="fingerprint_settings")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE,
                                     related_name="fingerprint_settings")
    auth_endpoint = models.URLField(max_length=500, blank=True,
                                    default=DEFAULT_ENDPOINT)
    serial_number = models.CharField(max_length=20, blank=True, default="0")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "fingerprint_settings"
        unique_together = [("user", "organization")]
        verbose_name_plural = "fingerprint settings"

    def __str__(self):
        return f"Fingerprint reader for {self.user} at {self.organization}"

    @property
    def is_configured(self):
        """A serial of "0" or blank is how "no reader" has always been spelled."""
        return bool(self.serial_number and self.serial_number != "0")


class UserSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="settings")
    # Demo mode masks the verification result on screen (blurred photo,
    # redacted fields) so a real ID can be shown to an audience. It is a
    # presentation setting only: the transaction logged for the verification
    # still records the real values.
    demo_mode = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_settings"

    def __str__(self):
        return f"Settings for {self.user}"


class Location(models.Model):
    # Names are unique WITHIN an organization, not site-wide: two
    # organizations will both want a "Main Office".
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE,
                                     related_name="locations")
    name = models.CharField(max_length=255)
    #: Short code naming this location inside an offline credential.
    #: `name` is a 255-character field and feeds an otherwise unbounded claim
    #: on a QR payload that is already at the limit of what a printed stamp
    #: can carry, so what goes into the credential is this, capped at six.
    #: Blank means the credential simply does not name a location.
    code = models.CharField(max_length=6, blank=True, default="")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "locations"
        unique_together = [("organization", "name")]
        ordering = ["name"]

    def __str__(self):
        return self.name


class TransactionType(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE,
                                     related_name="transaction_types")
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    #: Whether other organizations' User Records name this type. Off, they
    #: still see that the person was verified here, and when, but not for
    #: what: a type can be a sensitive category. The organization's own
    #: admins decide, because the type is theirs.
    shared_in_user_records = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "transaction_types"
        unique_together = [("organization", "name")]
        ordering = ["name"]

    def __str__(self):
        return self.name


# DEPRECATED: No longer used. Replaced by Transaction model. Kept for migration compatibility.
class VerificationEvent(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    result = models.CharField(max_length=20)  # "success" or "failure"
    transaction_type = models.CharField(max_length=255, blank=True, default="")
    transaction_type_ref = models.ForeignKey(TransactionType, on_delete=models.SET_NULL, null=True, blank=True)
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "verification_events"

    def __str__(self):
        return f"{self.result} - {self.transaction_type} ({self.created_at})"


class Transaction(models.Model):
    transaction_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    operator_national_id_number = models.CharField(max_length=16, blank=True, default="")
    operator_location = models.CharField(max_length=255, blank=True, default="")
    national_id_card_number = models.CharField(max_length=16, blank=True, default="")
    digital_national_id_number = models.CharField(max_length=20, blank=True, default="")
    given_name = models.CharField(max_length=255, blank=True, default="")
    middle_name = models.CharField(max_length=150, blank=True, default="")
    last_name = models.CharField(max_length=150, blank=True, default="")
    date_of_birth = models.CharField(max_length=20, blank=True, default="")
    place_of_birth = models.CharField(max_length=255, blank=True, default="")
    marital_status = models.CharField(max_length=50, blank=True, default="")
    sex = models.CharField(max_length=20, blank=True, default="")
    verification_timestamp = models.DateTimeField(auto_now_add=True)
    authentication_result = models.CharField(max_length=20, blank=True, default="")
    failure_detail = models.CharField(max_length=255, blank=True, default="")
    transaction_type = models.CharField(max_length=255, blank=True, default="")

    # Recorded on the row rather than inferred from the operator, who may hold
    # memberships in several organizations and may move between them.
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL,
                                     null=True, blank=True,
                                     related_name="transactions")
    #: True when a site admin performed this inside an organization they are
    #: not a member of, so an organization's log never appears to show an
    #: operator it never assigned.
    acting_as_site_admin = models.BooleanField(default=False)
    #: The same for an admin of every organization (User.is_all_org_admin),
    #: so the log says which of the two roles let them in.
    acting_as_all_org_admin = models.BooleanField(default=False)

    #: Raw eVerify key -> value, for every field this organization had set to
    #: "Log" when the verification ran. The named columns above are still
    #: written, and are written ONLY when their own field is logged; this
    #: carries the rest -- Blood Type, the two addresses, the face -- which
    #: have never had a column of their own. Empty on rows written before the
    #: field configuration existed, which is why the export falls back to the
    #: columns.
    logged_fields = models.JSONField(default=dict, blank=True)

    #: Who this transaction was about, as a keyed hash that names nobody --
    #: what User Records finds a person's transactions by, across
    #: organizations. Written on every row whatever the field settings say,
    #: and only from what eVerify returned in the session, never from what
    #: the browser posted. Blank where there was no verified person, and on
    #: rows from before it existed whose ID numbers were not logged. See
    #: accounts/user_records.py.
    subject_key = models.CharField(max_length=64, blank=True, default="",
                                   db_index=True)

    # FK references
    operator = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    location_ref = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True)
    transaction_type_ref = models.ForeignKey(TransactionType, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = "transactions"
        ordering = ["-verification_timestamp"]

    def __str__(self):
        return f"{self.transaction_id} - {self.transaction_type} ({self.verification_timestamp})"


class UserRecordsRead(models.Model):
    """One look at a person's User Records: who looked, for which organization,
    at whose history and how much of it.

    The list is a person's history across every organization, shown to
    whoever verifies them, so verifying somebody to read it -- an
    acquaintance, a former partner -- has to leave a trace. The person is
    the same keyed hash the transactions carry (`Transaction.subject_key`),
    never a number. Written by `views.core.user_records_api` and read-only
    in Django admin, like the transaction log.
    """

    operator = models.ForeignKey("User", on_delete=models.SET_NULL, null=True,
                                 related_name="+")
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL,
                                     null=True, related_name="+")
    subject_key = models.CharField(max_length=64, blank=True, default="")
    records = models.PositiveIntegerField(default=0)
    read_at = models.DateTimeField(default=timezone_now, db_index=True)

    class Meta:
        db_table = "user_records_reads"
        ordering = ["-read_at"]

    def __str__(self):
        return f"user {self.operator_id} read {self.records} records at {self.read_at}"


class SiteSettings(models.Model):
    """Site-wide administration settings. Exactly one row, id=1.

    Holds the login method for the whole site and, when that is single
    sign-on, the OIDC client credentials. The client secret is write-only: it is never
    rendered back into the Setup form, so it does not travel to a browser
    after it has been saved.

    It also holds the eVerify credentials that SIGN OPERATORS IN. Those are
    site-level by necessity: the login page runs before anybody has a session,
    so there is no organization yet whose client could be used. The
    credentials a verification runs against live on Organization instead --
    see the note there.
    """

    LOGIN_EVERIFY = "everify"
    LOGIN_SSO = "sso"
    LOGIN_MODES = [
        (LOGIN_EVERIFY, "Direct eVerify (National ID + liveness)"),
        (LOGIN_SSO, "Single sign-on (OpenID Connect)"),
    ]

    login_mode = models.CharField(
        max_length=16, choices=LOGIN_MODES, default=LOGIN_EVERIFY)

    #: How long a credential minted now is valid, in days: a document's cut-out
    #: card and a holder's credential alike. `credential_keys.validity_days()`
    #: is what reads it, inside the ceiling; a credential already issued keeps
    #: the date signed into it.
    DEFAULT_CREDENTIAL_VALIDITY_DAYS = 30
    credential_validity_days = models.PositiveSmallIntegerField(
        default=DEFAULT_CREDENTIAL_VALIDITY_DAYS)
    # No default provider: a new site must not point at somebody else's.
    sso_issuer = models.CharField(max_length=255, blank=True, default="")
    sso_client_id = models.CharField(max_length=255, blank=True, default="")
    sso_client_secret = models.CharField(max_length=255, blank=True, default="")

    # eVerify client used ONLY to sign operators in. Seeded from the .env
    # values by migration 0017 so the first deploy changes nothing.
    everify_base_url = models.CharField(
        max_length=255, blank=True, default="https://ws.everify.gov.ph/api")
    everify_client_id = models.CharField(max_length=255, blank=True, default="")
    everify_client_secret = models.CharField(max_length=255, blank=True, default="")
    everify_public_api_key = models.TextField(blank=True, default="")

    #: Whether this instance is currently keeping eVerify responses -- see
    #: `debug_store.capture_enabled()`. It is consulted ONLY where the two
    #: environment opt-ins are already set, and can therefore only turn the
    #: store OFF. A switch on a web form must never be able to start
    #: recording identity records on a deployment whose environment says it
    #: must not have them; the gate stays in the environment, and this is a
    #: pause button behind it. Default on, so an instance whose environment
    #: opens the gate captures until somebody pauses it.
    debug_capture_enabled = models.BooleanField(default=True)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "site_settings"
        verbose_name_plural = "site settings"

    def __str__(self):
        return f"Site settings ({self.get_login_mode_display()})"

    @classmethod
    def load(cls):
        """The single settings row, or unsaved defaults if it does not exist.

        Deliberately does NOT create the row. home() calls this on every hit
        of the login page, and a get_or_create there would be a write on a
        GET -- which is exactly what has to be removed before the app tier
        can serve reads from a replica (writes there surface as a disk I/O
        error). The row is written only when an admin saves Setup.
        """
        return cls.objects.filter(pk=1).first() or cls(pk=1)

    @property
    def everify_configured(self):
        """Enough to sign an operator in. Nothing here can verify anyone --
        that runs against the organization's own client."""
        return bool(self.everify_base_url and self.everify_client_id
                    and self.everify_client_secret)

    @property
    def sso_configured(self):
        """Both halves of the client credential are present, and the issuer is
        one this server allows (SSO_ALLOWED_ISSUERS). An issuer it does not
        allow is no SSO at all: the login page offers eVerify instead of
        handing sign-in to it."""
        from .sso_issuer import allowed
        return bool(self.sso_issuer and self.sso_client_id
                    and self.sso_client_secret and allowed(self.sso_issuer))

    @property
    def sso_issuer_refused(self):
        """An issuer is stored, and this server does not allow it."""
        from .sso_issuer import allowed
        return bool(self.sso_issuer) and not allowed(self.sso_issuer)

    @property
    def sso_login_active(self):
        """SSO is the chosen mode AND usable.

        Both conditions, deliberately. Selecting the mode without complete
        credentials must not open a login route that cannot verify anybody --
        it would fail open into a callback with no provider to check against.
        """
        return self.login_mode == self.LOGIN_SSO and self.sso_configured


class LoginAttempt(models.Model):
    """A sign-in attempt that was refused before eVerify was ever called.

    Only refused attempts land here, and refused means one thing: the
    National ID typed on the login page names no row in Users, so there is
    nobody it could sign in even if the upstream vouched for it. Calling
    eVerify for it would spend a liveness session and a query on somebody
    who cannot be let in either way, which is a quota-burn vector open to
    anyone who can reach the login page.

    A registered operator is NOT recorded here. Their attempt goes to the
    upstream, and if it fails it is logged as a Transaction like every
    other failure. Keeping the two apart is the point: this table is
    "people who are not us tried to get in", and it is the only place in
    the app that stores a face captured by the app itself.

    `photo_data` is a complete `data:image/...;base64,...` URI, for the same
    reason Organization.logo_data is (deploy/deploy.sh rsyncs to instances
    with no shared media volume). It is a face, so treat the table as
    sensitive: it is admin-only, it is never exported with transactions, and
    `purge_login_attempts` exists to age it out.
    """

    KIND_CARD = "card"
    KIND_DIGITAL = "digital"
    KIND_OTHER = "other"

    #: The ID as typed, stripped of dashes and spaces and upper-cased. Not a
    #: foreign key by design -- the whole point is that it matches no user.
    submitted_id = models.CharField(max_length=32, blank=True, default="")
    id_kind = models.CharField(max_length=16, blank=True, default=KIND_OTHER)

    #: The face the liveness check handed back. The eVerify iframe posts
    #: {photo, session_id, photo_url} to the parent window when it completes,
    #: so this is the upstream's own capture, not one this app took. Empty
    #: when the refusal happened somewhere no check had run -- a direct POST
    #: to /everify/, which is exactly what an enumeration script does.
    photo_data = models.TextField(blank=True, default="")

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "login_attempts"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["submitted_id"])]

    def __str__(self):
        return f"{self.submitted_id or '(blank)'} at {self.created_at}"

    @property
    def has_photo(self):
        return bool(self.photo_data)


class RateLimitHit(models.Model):
    """One counted request toward a per-address limit
    (accounts/throttle.py).

    Only a request within its limit writes a row, so a flood cannot fill
    this table; rows older than the longest window are pruned as new ones
    arrive. The key is the client's address as the nearest trusted proxy
    saw it, or "unknown".
    """

    scope = models.CharField(max_length=32)
    key = models.CharField(max_length=64)
    at = models.DateTimeField()

    class Meta:
        db_table = "rate_limit_hits"
        indexes = [models.Index(fields=["scope", "key", "at"]),
                   models.Index(fields=["at"])]

    def __str__(self):
        return f"{self.scope} from {self.key} at {self.at}"


class OrganizationFieldSetting(models.Model):
    """One organization's override of one eVerify field.

    A row exists only for a field somebody has actually configured. The
    canonical list, and every default, is in accounts/everify_fields.py --
    see rows_for(), which merges these over it. That is what lets a field
    added in code appear for every organization at once with no migration,
    and what keeps the whitelist a reviewed artefact rather than something
    typed into a form.

    ONE order, not two. The position below drives the document rows and the
    export columns alike; the export simply skips what is not logged. Two
    orders needed two lists to edit them in, and one list is easier to read
    than the flexibility was worth.
    """

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE,
                                     related_name="field_settings")
    #: eVerify's own key, e.g. "first_name" -- never the display name. The
    #: display name is editable, and matching on it would mean a rename
    #: silently stopped a field being logged.
    key = models.CharField(max_length=64)
    #: Blank means "use the built-in name", and failing that, the key.
    display_name = models.CharField(max_length=120, blank=True, default="")
    show_on_document = models.BooleanField(default=True)
    #: Ignored for a field that cannot be readily logged -- the face is an
    #: image, not a column value. rows_for() enforces that, so a stored True
    #: here can never put one in an export.
    include_in_log = models.BooleanField(default=True)
    position = models.IntegerField(default=0)

    class Meta:
        db_table = "organization_field_settings"
        unique_together = [("organization", "key")]
        ordering = ["organization", "position"]

    def __str__(self):
        return f"{self.organization.name}: {self.key}"


class CredentialEpochKey(models.Model):
    """One audience key pair for one epoch and one tier.

    The private half is NOT a secret from the verifier fleet -- every enrolled
    phone is given it, wrapped to its Secure Enclave, or it could not open a
    credential at all. What it is secret from is anyone who gets the database,
    which is why it is stored wrapped rather than raw: db.sqlite3 rides the off-site
    database backups.

    Rows are created on demand as epochs roll, never edited. A row that
    disappears takes with it every credential minted under it.
    """

    class Tier(models.IntegerChoices):
        PUBLIC = 0, "Public"
        RESTRICTED = 1, "Restricted"

    epoch = models.PositiveIntegerField()
    tier = models.PositiveSmallIntegerField(choices=Tier.choices)
    #: Raw 32-byte X25519 public key. Not secret: it is what a credential is
    #: encrypted TO, and it is in every credential's key schedule.
    public_key = models.BinaryField()
    #: AES-GCM under CREDENTIAL_EPOCH_WRAP_KEY, nonce prefixed.
    wrapped_private_key = models.BinaryField()
    not_before = models.DateTimeField()
    #: When phones stop carrying it -- the epoch's end plus the overlap, not
    #: the epoch's end, or the expiry of the last credential minted under it
    #: if that is later (`credential_keys.keep_readable_until`, which is the one
    #: edit a row takes). Past this a phone reports `device_stale`.
    not_after = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "credential_epoch_keys"
        unique_together = [("epoch", "tier")]
        ordering = ["-epoch", "tier"]

    def __str__(self):
        return "epoch %d %s" % (self.epoch, self.get_tier_display())


class IssuedCredential(models.Model):
    """Every offline credential this deployment has minted.

    THIS is the authoritative record. The sibling OfflineVerifier deployment
    keeps a copy so that its device bundles can carry a revocation filter, but
    the row here is the original.

    Claim VALUES are deliberately not stored. The QR is the credential, and
    the transaction it belongs to already holds whatever the organization
    chose to log; duplicating personal data into a third place would create a
    third thing to protect.
    """

    credential_id = models.UUIDField(unique=True, editable=False)
    #: The verification this was minted for. SET_NULL rather than CASCADE: a
    #: credential that exists in the world does not stop existing because a
    #: transaction row was tidied away, and revocation still has to find it.
    transaction = models.ForeignKey(Transaction, on_delete=models.SET_NULL,
                                    null=True, blank=True,
                                    related_name="credentials")
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL,
                                     null=True, blank=True,
                                     related_name="credentials")
    #: The transaction UUID, kept even if the transaction row goes: it is what
    #: the credential names itself by, and what the QR shows in the clear.
    document_uuid = models.UUIDField()
    epoch = models.PositiveIntegerField()
    issuer_key_id = models.PositiveIntegerField()
    issued_at = models.DateTimeField()
    expires_at = models.DateTimeField()

    #: When this was registered with the verifier fleet, so it can appear in
    #: the revocation filter phones carry. Null means it has not been, and
    #: revoking it would have no effect on a device.
    registered_at = models.DateTimeField(null=True, blank=True)

    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                   blank=True,
                                   related_name="revoked_credentials")
    revoked_reason = models.CharField(max_length=200, blank=True, default="")

    #: Written as PENDING before a signature is asked for, and SIGNED once it
    #: comes back -- so a credential the signer made is never missing here,
    #: even if the reply was lost. UNKNOWN is that lost reply: the request went
    #: out and nothing came back, so it may exist.
    STATE_PENDING = "pending"
    STATE_SIGNED = "signed"
    STATE_UNKNOWN = "unknown"
    STATE_CHOICES = [(STATE_PENDING, "Pending"), (STATE_SIGNED, "Signed"),
                     (STATE_UNKNOWN, "Unknown")]
    state = models.CharField(max_length=8, choices=STATE_CHOICES,
                             default=STATE_SIGNED)

    class Meta:
        db_table = "issued_credentials"
        ordering = ["-issued_at"]

    def __str__(self):
        return str(self.credential_id)


class RevokedCredentialId(models.Model):
    """A credential id revoked without ever having been issued here.

    For a forgery made with a trusted key: it is in no `IssuedCredential` row,
    yet phones must flag it. Rows are only ever added -- there is no
    un-revoke, for the reason `IssuedCredentialAdmin` gives.
    """

    credential_id = models.UUIDField(unique=True)
    reason = models.CharField(max_length=200, blank=True, default="")
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                 blank=True, related_name="+")
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "revoked_credential_ids"
        ordering = ["-added_at"]

    def __str__(self):
        return str(self.credential_id)


class RevocationState(models.Model):
    """One row: how many times the revoked set has changed.

    Every gunicorn worker caches the feed keyed by this number, so a
    revocation in one worker reaches every other at its next request,
    without scanning the revoked set on every unauthenticated poll.
    """

    generation = models.PositiveBigIntegerField(default=0)

    class Meta:
        db_table = "revocation_state"


class IssuerKey(models.Model):
    """A key credentials are signed with, as a device is told to trust it.

    The PEM on disk is the private half; this row is the public half plus the
    window it is good for, which is what goes into the trust list a device
    receives. They are separate because they have opposite lifetimes: the file
    is replaced during a rotation, while both rows must exist at once so
    credentials signed by the outgoing key keep verifying until they expire.

    `load_credential_keys` writes this from the sibling deployment's own
    registration, so the two cannot disagree about which key is which.

    **With a signer** (`SIGNER_SOCKET`) this is only a mirror of the signer's
    registry, refreshed from it, and nothing here decides anything: the signer
    builds the trust list itself. `is_active` then means "in the trust list",
    legacy keys included.
    """

    SOURCE_FILE = "file"
    SOURCE_SIGNER = "signer"

    key_id = models.PositiveIntegerField(unique=True)
    #: DER SubjectPublicKeyInfo, P-256.
    spki_der = models.BinaryField()
    #: The key's window: the only span a credential it signed may claim.
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    source = models.CharField(max_length=8, default=SOURCE_FILE)
    #: The signer's state for the key: published, active, suspended, ...
    state = models.CharField(max_length=16, blank=True, default="")
    #: The organization an organization key belongs to, by its signing id --
    #: not a foreign key, so the record outlasts the organization's deletion.
    organization_signing_id = models.UUIDField(null=True, blank=True)
    #: The O in an organization key's certificate: the issuer phones show.
    certified_name = models.CharField(max_length=255, blank=True, default="")
    subject = models.CharField(max_length=512, blank=True, default="")
    fingerprint_sha256 = models.CharField(max_length=64, blank=True,
                                          default="")
    certificate_chain = models.BinaryField(null=True, blank=True)
    cert_not_after = models.DateTimeField(null=True, blank=True)
    synced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "issuer_keys"
        ordering = ["key_id"]

    def __str__(self):
        return "issuer key %d" % self.key_id


class Device(models.Model):
    """A phone paired to somebody's account, holding the keys to read a
    credential offline.

    `public_key_der` is the device's Secure Enclave P-256 public key, bound
    here at enrolment. It is the device's whole identity: every later request
    is authenticated by a signature that key produces, so there is no bearer
    token to steal and replay, and nothing about who the caller is can be
    chosen by the caller.

    The owner is CASCADE, not SET_NULL. A device's access follows its owner,
    so an ownerless device is not a degraded device -- it is one whose tier
    nothing can answer. Deleting the person takes the phones with them.
    """

    device_id = models.UUIDField(default=uuid.uuid4, unique=True,
                                 editable=False)
    label = models.CharField(max_length=120)
    #: DER SubjectPublicKeyInfo, P-256, from the Secure Enclave. Unique: two
    #: rows claiming one key would make "which device is this" unanswerable.
    public_key_der = models.BinaryField(unique=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE,
                              related_name="devices")

    #: App Attest. The key id the phone named, the key attested at pairing --
    #: which every assertion is checked against, never the Enclave key -- the
    #: last assertion's counter, and what the checks found: "" not checked
    #: (paired before they were), "attested", "absent" (the phone sent none),
    #: "unconfigured" (no app id here) or "failed", which stays until the
    #: phone pairs again.
    attest_key_id = models.CharField(max_length=200, blank=True, default="")
    attest_counter = models.PositiveIntegerField(default=0)
    attest_public_key_der = models.BinaryField(null=True, blank=True,
                                               editable=False)
    attest_status = models.CharField(max_length=20, blank=True, default="")
    attest_detail = models.CharField(max_length=200, blank=True, default="")
    attest_checked_at = models.DateTimeField(null=True, blank=True)

    enrolled_at = models.DateTimeField(auto_now_add=True)
    last_sync_at = models.DateTimeField(null=True, blank=True)
    #: When the keys this device holds stop being refreshed. A lease that has
    #: run out is not a revocation: the phone simply has to sync.
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    #: The last sync at which the phone said it understands issuer
    #: certificates (`capabilities: ["issuer-chain"]`). A key may switch only
    #: once every live phone has, or a lease has passed.
    issuer_chain_capable_at = models.DateTimeField(null=True, blank=True)

    #: What the Devices page says about App Attest, by `attest_status`.
    ATTEST_LABELS = {
        "": "not checked",
        "attested": "passed",
        "absent": "not sent",
        "unconfigured": "not configured here",
        "failed": "FAILED",
    }

    @property
    def attest_label(self):
        return self.ATTEST_LABELS.get(self.attest_status, self.attest_status)

    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                   blank=True, related_name="revoked_devices")
    revoked_reason = models.CharField(max_length=200, blank=True, default="")

    #: A CAP, never a grant: True means this phone is sent the public tier and
    #: nothing more, whatever its owner is entitled to. Set on every phone
    #: registered from idmanager (accounts/holders.py).
    #:
    #: This does not move the tier off the person -- `restricted_tier` still
    #: reads the owner every time, and withdrawing it there still reaches
    #: every phone. It only means one path can never raise access: a phone
    #: that arrived on idmanager's word, rather than through this site's own
    #: pairing, is not trusted with other people's details, so a compromise
    #: of idmanager's signing key yields public-tier phones and nothing else.
    public_tier_only = models.BooleanField(default=False)

    class Meta:
        db_table = "devices"
        ordering = ["-enrolled_at"]

    def __str__(self):
        return self.label or str(self.device_id)

    @property
    def is_active(self):
        return self.revoked_at is None

    @property
    def keys_stale(self):
        """Its lease has run out, so it must sync before it can be trusted.

        NOT a revocation, and must not be shown as one: the phone simply has
        to check in. Saying otherwise would send somebody to revoke a device
        that only needed opening.
        """
        from django.utils import timezone

        return bool(self.lease_expires_at
                    and self.lease_expires_at <= timezone.now())

    @property
    def restricted_tier(self):
        """Read from the OWNER, every time, never cached on this row.

        That is what makes withdrawing somebody's access reach every phone
        they hold at its next sync, instead of requiring each one to be found.

        `public_tier_only` can only take it away -- see that field.
        """
        if self.public_tier_only:
            return False
        return bool(self.owner and self.owner.device_restricted_tier)


class DeviceOrganization(models.Model):
    """One phone working for one organization, from a time, until a time.

    **The organization is the context the operator works in, not a filter.**
    A phone linked to one organization still reads every organization's
    credentials; what a link decides is which
    organizations the app offers in its "Select your organization" chooser,
    and so which organization each of its log records names. Nothing here
    is a grant of access, so nothing here is checked when a document is read.

    **Unlinking ends a row; it never deletes one.** A phone queues records
    offline and uploads them later, so a record written while the phone
    worked for an organization can arrive after the link ended -- and it
    must still be filed under that organization. `device_log.ingest`
    attributes a record when the phone has ANY row for the organization it
    names, current or past, and only a kept row can answer that. Linking
    again creates a new row, so the history reads as the periods it was.

    At most one CURRENT row per (phone, organization), enforced by the
    database rather than by the view, so a double-submitted form cannot
    leave two.

    What the phone is told is narrower than what is stored: a link to an
    organization the owner may no longer enter is simply not sent
    (`devices.organizations_for`), and comes back if the membership does.
    """

    device = models.ForeignKey(Device, on_delete=models.CASCADE,
                               related_name="organization_links")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE,
                                     related_name="device_links")
    linked_at = models.DateTimeField(auto_now_add=True)
    #: Null for the links migration 0038 made for phones paired before
    #: organizations were linked at all: nobody chose those, they were the
    #: state of things.
    linked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                                  blank=True, related_name="+")
    unlinked_at = models.DateTimeField(null=True, blank=True)
    unlinked_by = models.ForeignKey(User, on_delete=models.SET_NULL,
                                    null=True, blank=True, related_name="+")

    class Meta:
        db_table = "device_organizations"
        ordering = ["-linked_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["device", "organization"],
                condition=models.Q(unlinked_at__isnull=True),
                name="device_organization_one_current_link"),
        ]

    def __str__(self):
        return "%s for %s%s" % (self.device, self.organization,
                                "" if self.is_current else " (ended)")

    @property
    def is_current(self):
        return self.unlinked_at is None


class DeviceTicket(models.Model):
    """A one-time code that hands ONE management operation to a phone.

    It exists to keep the authenticated step on the web, where a session and
    CSRF apply, and out of the app. The person signs in, asks for the
    operation, and the phone presents the code once. Afterwards the device
    authenticates by signing a server-issued challenge and never carries a
    bearer credential again.

    Not a secret worth protecting for long: single-use, short-lived, and
    worthless once spent. What it authorises is exactly the one `purpose` it
    was minted for -- a sync ticket cannot enrol a phone and an enrolment
    ticket cannot re-key one, because every endpoint checks the purpose rather
    than merely that the code is live.

    This began as `EnrolmentCode`, which is why the table has a history of
    pairing codes in it. The generalisation is deliberate: the QR is the way
    a management operation is handed to a phone, and pairing is only the
    first such operation.
    """

    PURPOSE_ENROL = "enrol"
    PURPOSE_REKEY = "rekey"
    PURPOSE_SYNC = "sync"
    PURPOSES = [
        (PURPOSE_ENROL, "Pair a new phone"),
        (PURPOSE_REKEY, "Replace a phone's key"),
        (PURPOSE_SYNC, "Refresh a phone's keys"),
    ]
    #: Operations on a phone that already exists. A ticket for one of these
    #: names the device it acts on, and is refused without it -- otherwise
    #: "re-key" would have no answer to "re-key what".
    DEVICE_SCOPED = (PURPOSE_REKEY, PURPOSE_SYNC)

    CODE_LENGTH = 8
    #: No I, O, 0 or 1. Somebody may read this aloud or type it from a screen,
    #: and a mis-keyed character costs a support call.
    ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    code = models.CharField(max_length=16, unique=True, editable=False)
    purpose = models.CharField(max_length=16, choices=PURPOSES,
                               default=PURPOSE_ENROL)
    label = models.CharField(max_length=120, blank=True, default="")
    #: CASCADE: an open ticket is worthless once its account is gone, and
    #: leaving it usable would pair a phone to nobody.
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name="device_tickets")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    #: The device this ticket concerns: named at minting for a device-scoped
    #: purpose, and filled in afterwards by an enrolment. One field, because
    #: in both directions it answers the same question. SET_NULL keeps the
    #: record of a pairing whose phone has since been deleted; a device-scoped
    #: ticket left pointing at nothing is refused by `purpose` alone.
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True,
                               blank=True, related_name="tickets")
    #: For an ENROL ticket only: the organizations the new phone starts out
    #: working for -- ticked on the pairing form, which pre-ticks the one the
    #: person is working in. `enrol()` links each the owner may STILL enter
    #: when the phone arrives, since a membership can end between the QR and
    #: the scan. Sync and re-key tickets leave links alone: a phone that
    #: exists has its links changed on the Devices page, not by a QR.
    organizations = models.ManyToManyField(Organization, blank=True,
                                           related_name="device_tickets")

    class Meta:
        db_table = "device_tickets"
        ordering = ["-created_at"]

    def __str__(self):
        return "%s (%s)" % (self.code, self.purpose)

    @property
    def is_spent(self):
        from django.utils import timezone

        return self.used_at is not None or self.expires_at <= timezone.now()

    @classmethod
    def new_code(cls):
        import secrets

        while True:
            code = "".join(secrets.choice(cls.ALPHABET)
                           for _ in range(cls.CODE_LENGTH))
            if not cls.objects.filter(code=code).exists():
                return code


class DeviceChallenge(models.Model):
    """A single-use nonce a device signs to prove it holds its Enclave key.

    Issued to anyone who asks, because the nonce alone grants nothing -- only
    a signature over it does, and that needs a key this server never had.
    Consumed on use, so a captured exchange cannot be replayed.
    """

    nonce = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "device_challenges"
        ordering = ["-created_at"]

    def __str__(self):
        return self.nonce


class DeviceLogKey(models.Model):
    """The X25519 key pair a verifier phone seals its activity log to.

    A phone is handed only the PUBLIC half, in a statement the issuer key
    signs (`accounts/device_log.py::key_statement`), and seals every record
    to it the moment the record is written. The private half never leaves
    this deployment, so a compromised phone holds ciphertext it cannot read
    back -- which is the whole point of the log (see `ovcrypto/devicelog.py`).

    **The id IS the wire `key_id`**, the four bytes in every record's header
    naming which key it was sealed to. An explicit 32-bit `AutoField` rather
    than the project's 64-bit default, so the column cannot hold an id the
    record header has no room for.

    **Custody: wrapped in this database, under the epoch wrapping key.** The
    private half is stored exactly as `CredentialEpochKey` stores an epoch
    key -- `credential_keys._wrapper()`, AES-256-GCM under
    `CREDENTIAL_EPOCH_WRAP_KEY` -- for two reasons:

    * what this key opens is stored in this same database the moment it is
      opened (`DeviceLogEntry`), so a key file kept outside it would protect
      nothing the database does not already hold in the clear;
    * it needs no new deploy secret: a deployment that can mint credentials
      can already wrap and unwrap this.

    `keystore.FileKeyWrapper` takes no associated data -- its AAD is the fixed
    `WRAP_AAD`, and `ovcrypto/` is a verbatim copy that is not edited here --
    so a wrapped log key and a wrapped epoch key are indistinguishable
    ciphertexts. That costs nothing: both live in the same database, and
    swapping one row's bytes into another table gains an attacker who can
    already write to it nothing new.

    **Never deleted, only retired.** A retired key is no longer handed out,
    but records sealed to it before the phone fetched a new statement must
    still open, so `device_log.private_keys()` returns every row.
    """

    id = models.AutoField(primary_key=True)
    #: Raw 32-byte X25519 public key. Not secret: it is in the statement.
    public_key = models.BinaryField()
    #: AES-GCM under CREDENTIAL_EPOCH_WRAP_KEY, nonce prefixed.
    wrapped_private_key = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    #: Stops it being handed out. Records already sealed to it still open.
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "device_log_keys"
        ordering = ["-id"]

    def __str__(self):
        return "device log key %d" % self.id


class DeviceLogEntry(models.Model):
    """One record from a verifier phone's activity log, opened.

    Uploaded by the phone, signed by its Enclave key, opened here with
    `DeviceLogKey` -- see `accounts/device_log.py::ingest` for every rule.

    **Snapshots, not just foreign keys.** The device, its label and its
    owner's name and card number are copied in at upload, and the foreign
    keys are SET_NULL. A phone that is deleted, or an owner removed (which
    cascades to their phones), must not take the record of what that phone
    did with it: an audit trail that the audited party can erase by being
    deleted is not one.

    **Two times, both kept.** `occurred_at` is what the PHONE's clock said;
    `received_at` is this server's. The phone's clock is the phone's to set,
    and records queue offline, so neither replaces the other -- a gap between
    them is a finding, not a rounding error. A claimed time that is not a
    plausible one is kept in `detail` and `occurred_at` left empty, rather
    than either being trusted or thrown away.

    **A record that does not open is still a row** (`readable` False), so the
    sequence stays continuous and the phone's upload is never refused for it.
    `chain_ok` says whether this record named the one before it, by hash.
    """

    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True,
                               blank=True, related_name="log_entries")
    device_uuid = models.UUIDField()
    device_label = models.CharField(max_length=120, blank=True, default="")
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True,
                              blank=True, related_name="device_log_entries")
    owner_name = models.CharField(max_length=255, blank=True, default="")
    owner_national_id_number = models.CharField(max_length=16, blank=True,
                                                default="")
    #: The phone's own record number, from 1, as the sealed header says.
    seq = models.PositiveBigIntegerField()
    #: Which DeviceLogKey it was sealed to.
    key_id = models.PositiveIntegerField()
    event = models.CharField(max_length=40)
    outcome = models.CharField(max_length=12)
    detail = models.JSONField(default=dict, blank=True)
    app_build = models.CharField(max_length=40, blank=True, default="")
    #: The DEVICE's claimed time. Null when it claimed something implausible.
    occurred_at = models.DateTimeField(null=True, blank=True)
    #: This server's time, when the upload carrying it arrived.
    received_at = models.DateTimeField(default=timezone_now, db_index=True)
    #: SHA-256 of the sealed record: what the next record names as `prev`.
    record_hash = models.BinaryField(max_length=32)
    chain_ok = models.BooleanField()
    readable = models.BooleanField(default=True)

    #: The organization the phone was working for when it wrote this record,
    #: when the record named one AND the phone has ever been linked to it
    #: (`device_log.ingest`). A record's `org` is the phone's claim, and a
    #: phone may be compromised -- the link is what keeps a phone from filing
    #: records into the export of an organization its owner never had it
    #: work for. SET_NULL with the name kept beside it, like the snapshots
    #: above, so deleting an organization does not unsay what was done.
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL,
                                     null=True, blank=True,
                                     related_name="device_log_entries")
    #: The organization's name when the record arrived.
    organization_name = models.CharField(max_length=255, blank=True,
                                         default="")
    #: The record's `org`, exactly as sent, attributed or not. A claim that
    #: matched no link is a finding (the export says "#<id> (not linked)"),
    #: never a reason to refuse the record.
    claimed_organization_id = models.PositiveIntegerField(null=True,
                                                          blank=True)

    class Meta:
        db_table = "device_log_entries"
        ordering = ["device_uuid", "seq"]
        constraints = [
            models.UniqueConstraint(fields=["device_uuid", "seq"],
                                    name="device_log_entry_one_per_seq"),
        ]

    def __str__(self):
        return "%s #%d %s" % (self.device_label or self.device_uuid,
                              self.seq, self.event)


class DeviceLogMark(models.Model):
    """How far `purge_device_logs` has aged one phone's log out: the
    highest-numbered record it deleted, by number and hash.

    No record's contents, so it outlives the retention period. Without it a
    purge takes the chain's head with it: the phone's next record would read
    as a break, a record sent again would be stored again, for another full
    period, and a rewritten one would be no conflict. `device_log.ingest`
    judges the chain from whichever is newer, this or the newest record
    held, and recognises a number at or below it without storing it.
    """

    device_uuid = models.UUIDField(unique=True)
    head_seq = models.PositiveBigIntegerField()
    head_hash = models.BinaryField(max_length=32)

    class Meta:
        db_table = "device_log_marks"

    def __str__(self):
        return "%s aged out through #%d" % (self.device_uuid, self.head_seq)


class HolderAssertion(models.Model):
    """Every idmanager assertion this deployment has accepted, once each.

    Two jobs. `jti` is unique, so an assertion is spent the first time it is
    presented: one captured in transit registers nothing a second time, and
    the unique index -- not a check-then-insert -- is what wins a race. And
    the rows are the record of whose phone was registered on idmanager's word,
    when, and on the strength of a check made when, which is the question an
    audit of this path will ask.

    Nothing here is a secret. The assertion itself is not stored -- only what
    it said about itself -- and it is worthless once spent anyway.
    """

    jti = models.CharField(max_length=64, unique=True, editable=False)
    issuer = models.CharField(max_length=255)
    key_id = models.CharField(max_length=64)
    #: idmanager's own id for the person. Opaque here; kept so the two
    #: systems' records can be lined up.
    subject = models.CharField(max_length=255)
    user = models.ForeignKey(User, on_delete=models.CASCADE,
                             related_name="holder_assertions")
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True,
                               blank=True, related_name="holder_assertions")
    #: When idmanager says the person passed eVerify and liveness.
    verified_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "holder_assertions"
        ordering = ["-accepted_at"]

    def __str__(self):
        return "%s from %s" % (self.jti, self.issuer)


class DebugCapture(models.Model):
    """A whole eVerify response, kept on a DEVELOPMENT instance only.

    Every measurement of what fits on a printed document -- the QR stamp
    size, the portrait's resolution and quality, the density tiers -- needs
    real data. Measuring on `static/mock-face.png` gives wrong answers: it is
    a cartoon smiley and compresses nothing like skin.

    So a development instance keeps what the upstream actually returned.
    `accounts/debug_store.py`
    holds the gate, the writer and the sizing report; `manage.py debug_sizes`
    is what reads this table.

    **It is a table of complete identity records with faces attached.** It is
    written only where BOTH opt-ins are set -- see `debug_store.debug_allowed`
    -- it is admin-only and read-only, it is never part of any export, and it
    is meant to be emptied as soon as a study is done:

        python manage.py debug_cleanup

    or the button on `/debug-cleanup/`, which exists only where the gate is
    open. Nothing ages it out on a timer; a debug store that quietly keeps
    real people for ninety days is the thing this docstring is warning about.
    """

    PURPOSE_LOGIN = "login"
    PURPOSE_VERIFY = "verify"

    OUTCOME_SUCCESS = "success"
    OUTCOME_FAILURE = "failure"

    created_at = models.DateTimeField(auto_now_add=True)
    #: Which of the two things POST /everify/ does produced this -- signing an
    #: operator in, or running a verification. Only the second carries a full
    #: demographic record, and it is the one the sizing work needs.
    purpose = models.CharField(max_length=16, default=PURPOSE_VERIFY)
    #: EVERY key the response carried, not the app's whitelist -- the point is
    #: to see what the upstream sends that this app does not yet carry.
    #: `face_url` is dropped: it is a signed URL that expires, and the image
    #: it pointed at is in photo_data.
    payload = models.JSONField(default=dict, blank=True)
    #: The face as `_prepare_data_for_frontend` left it: a complete
    #: `data:image/...;base64,...` URI, the same bytes the document rendered.
    photo_data = models.TextField(blank=True, default="")
    #: Whose field configuration was in play, so a sizing run can use the same
    #: list the real document would have. Null for the login path, which runs
    #: before there is an organization at all.
    organization = models.ForeignKey(Organization, null=True, blank=True,
                                     on_delete=models.SET_NULL,
                                     related_name="+")

    #: What the lookup came to. A failure is kept for a different reason than
    #: a success: a success is data to measure the printed document against,
    #: a failure is the record of an upstream that stopped answering, kept
    #: while it is fresh. It carries no identity: eVerify's error bodies
    #: are {error, error_description, message}, and nothing from the caller's
    #: own request is written here.
    outcome = models.CharField(max_length=16, default=OUTCOME_SUCCESS)
    #: The upstream's HTTP status, where it gave one. Null for a call that
    #: never got an answer at all.
    status_code = models.IntegerField(null=True, blank=True)
    #: One line, in the app's own words, of what happened. Never an identity.
    detail = models.CharField(max_length=200, blank=True, default="")

    class Meta:
        db_table = "debug_captures"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.purpose} capture at {self.created_at}"

    @property
    def has_photo(self):
        return bool(self.photo_data)

    @property
    def failed(self):
        return self.outcome == self.OUTCOME_FAILURE

    @property
    def field_count(self):
        return len(self.payload or {})


class CardHandoff(models.Model):
    """One verification, held just long enough for a phone to fetch it.

    The document page shows a QR pointing at `/card/<token>/`. The holder's
    own phone scans it, draws the portrait card and saves it to Photos. The
    phone has no account here and never will, so the token IS the
    authorisation -- there is nothing else it could present.

    **That makes this the one unauthenticated endpoint in the app that serves
    an identity**, which the revocation feed and the challenge endpoint
    deliberately do not. Four things keep it proportionate, and all four are
    load-bearing together:

    | | |
    |---|---|
    | 122 bits of UUID4 | there is nothing to guess and nothing to enumerate |
    | `CARD_HANDOFF_TTL_SECONDS` | five minutes, and the row is gone |
    | released on `pagehide` | the ordinary case ends the moment the operator leaves the document |
    | never listed | no listing page, no view that returns more than the one row asked for |

    **It holds the payload rather than a pointer to the transaction**, and
    that is a deliberate cost. The credential string and the rendered face
    are minted once and are not stored anywhere else -- rebuilding them on
    fetch would mean minting a SECOND credential, with a second
    `IssuedCredential` row, for one document. So an identity sits in
    `db.sqlite3` for a few minutes, and `db.sqlite3` rides the off-site database
    backups. `purge_expired()` runs on every open and `release()` deletes on
    the way out, so the steady state of this table is empty -- unlike
    `login_attempts`, which is an audit trail with a retention policy and is
    deliberately NOT aged out automatically. This one is a hand-off, not a
    record, and a hand-off nobody collected is worth nothing.

    Demo Mode reaches in here for the same reason it reaches into
    `_mint_credential()`: the card follows the DOCUMENT. What is saved to a
    phone is what the projector was showing -- masked rows, resampled face --
    and it is decided on the server from the operator, never from a flag in
    the request.
    """

    token = models.UUIDField(primary_key=True, default=uuid.uuid4,
                             editable=False)
    #: Everything the card draws: the two symbol payloads, the holder, the
    #: three context strings and the face as a data URI. Already masked when
    #: the operator was presenting.
    payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    #: Indexed because `purge_expired()` filters on it on EVERY open. Without
    #: the index that purge reads the whole table, and the table holds every
    #: hand-off of the last five minutes: harmless at a few hundred
    #: verifications a minute, half a million rows read per verification at
    #: 100,000. The index lets the purge read only what it deletes.
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        db_table = "card_handoffs"
        ordering = ["-created_at"]

    def __str__(self):
        return f"card handoff {self.token}"


class SignerJob(models.Model):
    """One request for a credential signer that dials out to this site.

    Where the signer cannot sit beside gunicorn -- app servers replaced at
    every release -- it long-polls this site instead (`SIGNER_QUEUE_KEY`,
    `accounts.signer_queue`, signer/deploy/README.md, "Poll mode"). The app
    server that needs a signature writes the request here, in the database
    every app server shares; whichever server the signer's poll lands on
    claims it; the signer posts the answer to whichever server, and the app
    server that wrote the job reads it here.

    `request` and `answer` are the JSON texts the socket would have carried,
    kept as text so the answer read here is byte for byte the socket's.

    The steady state of this table is empty, as `card_handoffs`' is: a job is
    deleted as soon as its answer is read or it is given up on, and
    `signer_queue.purge()` removes any a killed process left behind. While it
    waits it can hold what a signer signs -- a credential's bytes, a phone's
    wrapped epoch keys -- so it is never kept.
    """

    request = models.TextField()
    created_at = models.DateTimeField()
    #: Past this, the signer is not handed it and the app gives up on it.
    expires_at = models.DateTimeField(db_index=True)
    #: Set once, by the poll that handed it to the signer: a job is never
    #: handed out twice, so a signer that died holding it cannot sign it again.
    claimed_at = models.DateTimeField(null=True, blank=True)
    #: Which poll claimed it, so that poll can read back what it won.
    claim = models.CharField(max_length=32, blank=True, default="",
                             db_index=True)
    answer = models.TextField(blank=True, default="")
    answered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "signer_jobs"
        indexes = [models.Index(fields=["claimed_at", "expires_at"],
                                name="signer_jobs_pending")]

    def __str__(self):
        return f"signer job {self.pk}"


class SignerNonce(models.Model):
    """A nonce the poll-mode signer has used, so a request is never replayed.

    Kept in the database because a replay may land on any app server. A
    request's time must be within `poll.SKEW_SECONDS` of the server's, so a
    nonce is kept for a few minutes more than twice that and purged after;
    the newest row is also when the signer was last heard from
    (`signer_queue.alive`), and `signer` which signer polled
    (`signer_queue.pollers`). Times are the database's.
    """

    nonce = models.CharField(max_length=64, unique=True)
    seen_at = models.DateTimeField(db_index=True)
    #: The instance id a poll names (`poll.instance_id`); empty on an answer.
    signer = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        db_table = "signer_nonces"

    def __str__(self):
        return f"signer nonce {self.nonce[:8]}"
