"""Offline security contract for the dormant signing workflow."""
import pathlib
import unittest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]

class SigningWorkflow(unittest.TestCase):
    def setUp(self):
        self.w = yaml.safe_load((ROOT / '.github/workflows/windows-signing.yml').read_text())

    def test_manual_only(self):
        self.assertEqual(self.w.get('on', self.w.get(True)), {'workflow_dispatch': None})
        self.assertEqual(self.w['permissions'], {'contents': 'read'})

    def test_trusted_tag_and_explicit_enrollment(self):
        job = self.w['jobs']['sign']
        for guard in ("github.repository == 'VACInc/pushgate'", "startsWith(github.ref, 'refs/tags/win-v')", "vars.SIGNPATH_READY == 'true'"):
            self.assertIn(guard, job['if'])
        self.assertEqual(job['environment'], 'windows-signing')
        self.assertFalse('self-hosted' in str(self.w))

    def test_sign_only_build_artifact(self):
        steps = self.w['jobs']['sign']['steps']
        upload = next(s for s in steps if s.get('id') == 'unsigned')
        self.assertEqual(upload['with']['path'], 'windows/build/PushGateWin.dll')
        sign = next(s for s in steps if 'SignPath/' in s.get('uses', ''))
        self.assertEqual(sign['with']['github-artifact-id'], '${{ steps.unsigned.outputs.artifact-id }}')
        self.assertTrue(sign['with']['wait-for-completion'])
        self.assertFalse(any('SIGNPATH_API_TOKEN' in str(s) for s in steps if s != sign))

    def test_verify_fails_closed(self):
        self.assertEqual(self.w['jobs']['verify']['needs'], 'sign')
        script = self.w['jobs']['verify']['steps'][-1]['run']
        for check in ("$s.Status -ne 'Valid'", '$s.SignerCertificate.Thumbprint -ne $env:EXPECTED_SIGNER', 'if (-not $s.TimeStamperCertificate)', 'if ($LASTEXITCODE -ne 0)'):
            self.assertIn(check, script)
        self.assertNotIn('continue-on-error', str(self.w))

    def test_pinned_actions_and_no_publish(self):
        import re
        for job in self.w['jobs'].values():
            for step in job['steps']:
                if 'uses' in step:
                    self.assertRegex(step['uses'], r'@[a-f0-9]{40}$')
        self.assertNotIn('contents: write', str(self.w))

if __name__ == '__main__':
    unittest.main()
