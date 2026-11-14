"""The credential signer's own tests, run with verify's.

`signer/` is Django-free and is tested with plain unittest; it is imported
here so `manage.py test accounts` runs it too. One check needs both sides: the
feed the signer signs must be byte for byte the layout verify serves.
"""

from django.test import SimpleTestCase

from signer import messages
from signer.tests.test_e2e import EndToEndVectorTest  # noqa: F401
from signer.tests.test_held import (  # noqa: F401
    HeldKeyTest, HeldPolicyFileTest, LocalLedgerTest)
from signer.tests.test_names import (  # noqa: F401
    DeploymentKeyIssuerTest, InstalledCertificateNameTest, LookAlikeNameTest,
    NameUniquenessTest)
from signer.tests.test_operations import (  # noqa: F401
    AlertOnceTest, CheckTest, InternalFailureTest, KeyIdTest, OperatorCheckTest,
    ReconcileSpanTest, StoreLockTest, UnitTest)
from signer.tests.test_poll import (  # noqa: F401
    AwsCredentialsTest, DeployFilesTest, InstanceIdTest, MacTest,
    PollCheckTest, PollerTest, ReconcileWithoutAReportTest, ReportTargetTest,
    RetentionTest, ServiceNoticeTest, TransportPolicyTest)
from signer.tests.test_org_ca import (  # noqa: F401
    DiscardTest, GenerateTest, OrganizationCATest, PkiRequestTest,
    SiteCheckTest, SiteDomainPolicyFileTest, SystemCADomainTest)
from signer.tests.test_runtime import (  # noqa: F401  (collected by the runner)
    DeployUnitTest, DispatcherFailureTest, DispatcherTest, LoopTest,
    ReconcileRunTest, ReconcileTest, ShipUnderLockTest, ShipperTest,
    UnixSocketTest)
from signer.tests.test_rebuild import (  # noqa: F401
    AdoptTest, StartOrderTest, StatusCodeTest, VersionTest, WatchTest)
from signer.tests.test_site_controls import (  # noqa: F401
    HeldKeyControlsTest, OffByDefaultTest, SiteControlsPolicyFileTest,
    SiteControlsTest, SuspendAttributionTest)
from signer.tests.test_site_publish import (  # noqa: F401
    SitePublishEdgeCasesTest, SitePublishPolicyFileTest, SitePublishTest)
from signer.tests.test_switching import (  # noqa: F401
    CertifiedSwitchTest, GateNeededTest, OldAppTest, PolicyWindowTest,
    RetireTest, UncountedGateTest, WindowEndTest)
from signer.tests.test_service import (  # noqa: F401
    AlertDeliveryTest, BundleTest, CeilingTest, CertificateBindingTest,
    CredentialPolicyTest, HolderCeilingTest, LedgerTest, LifecycleTest,
    LogKeyBindingTest, OrganizationKeyTest, RevocationAndFeedTest,
    SnsTimeoutTest, StatementTest)


class FeedLayoutTest(SimpleTestCase):

    def test_the_signer_and_verify_sign_the_same_feed_bytes(self):
        from accounts import revocation_feed

        args = (1_800_000_000, 1_800_086_400, 16, b"CL03RF-filter")
        # Both come from ovcrypto.feed, so comparing them with each other
        # proves nothing: each is held to the layout written out here.
        layout = (b"OfflineVerifier/v1/revocation\x00" + b"CL03RL" + b"\x01"
                  + (1_800_000_000).to_bytes(4, "big")
                  + (1_800_086_400).to_bytes(4, "big")
                  + (16).to_bytes(4, "big") + len(b"CL03RF-filter").to_bytes(4, "big")
                  + b"CL03RF-filter")
        self.assertEqual(messages.feed_signed_bytes(*args), layout)
        self.assertEqual(revocation_feed.signed_bytes(*args), layout)
        self.assertEqual(messages.FEED_CONTEXT, revocation_feed.SIG_CONTEXT)
