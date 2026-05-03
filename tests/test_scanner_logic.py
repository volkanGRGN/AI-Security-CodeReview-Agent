import unittest
from pathlib import Path

from scanner.config import apply_config_to_project, load_baseline, load_config
from scanner.detector import ProjectDetector
from scanner.runner import SecurityRunner


FIXTURES = Path(__file__).resolve().parent / 'fixtures'


class ScannerLogicTests(unittest.TestCase):
    def scan(self, repo: Path, config=None):
        config = config or load_config(repo)
        project_info = apply_config_to_project(ProjectDetector(repo).detect(), config)
        runner = SecurityRunner(repo, project_info, config)
        return project_info, runner.run_all_checks()

    def test_cli_repo_skips_unrelated_domains(self):
        project_info, _ = self.scan(FIXTURES / 'cli_repo')

        self.assertEqual(project_info['arch_types'], ['cli'])
        self.assertIn('core', project_info['security_domains'])
        self.assertIn('secrets', project_info['security_domains'])
        self.assertIn('code_quality', project_info['security_domains'])
        self.assertIn('web', project_info['skipped_domains'])
        self.assertIn('mobile', project_info['skipped_domains'])
        self.assertIn('embedded', project_info['skipped_domains'])
        self.assertIn('ai_ml', project_info['skipped_domains'])

    def test_web_repo_enables_web_domain(self):
        project_info, _ = self.scan(FIXTURES / 'web_repo')

        self.assertIn('web', project_info['security_domains'])
        self.assertNotIn('web', project_info['skipped_domains'])

    def test_config_can_force_include_and_exclude_domains(self):
        config = load_config(FIXTURES / 'config_repo')
        project_info, _ = self.scan(FIXTURES / 'config_repo', config)

        self.assertIn('ai_ml', project_info['security_domains'])
        self.assertNotIn('web', project_info['security_domains'])
        self.assertIn('web', project_info['skipped_domains'])

    def test_securityignore_suppresses_matching_files(self):
        _, findings = self.scan(FIXTURES / 'ignored_repo')

        self.assertFalse(any(f['file'] == 'ignored.py' for f in findings))

    def test_terminal_word_is_not_langchain_tool_false_positive(self):
        config = {
            'include_domains': ['ai_ml'],
            'exclude_domains': [],
            'ignore_patterns': [],
            'baseline_file': None,
            'dependency_audit': {'enabled': False},
            'config_path': None,
            'fail_threshold': 'CRITICAL',
        }

        _, findings = self.scan(FIXTURES / 'terminal_repo', config)

        self.assertFalse(any(f['id'] == 'AIML-007' for f in findings))

    def test_existing_tests_suppress_missing_tests_noise(self):
        _, findings = self.scan(FIXTURES / 'tested_repo')

        self.assertFalse(any(f['id'] == 'CQ-050' for f in findings))

    def test_baseline_loads_finding_keys(self):
        keys = load_baseline(FIXTURES / 'baseline_repo', '.security_baseline.json')

        self.assertIn('A03-005:main.py:1', keys)


if __name__ == '__main__':
    unittest.main()
