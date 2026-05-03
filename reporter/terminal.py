"""
Terminal Reporter - colored, readable output for the security scan.
Uses ASCII-only output so it works on Windows terminals without UTF-8 setup.
"""

from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_COLORS = {
    'CRITICAL': Fore.RED + Style.BRIGHT,
    'HIGH': Fore.RED,
    'MEDIUM': Fore.YELLOW,
    'LOW': Fore.CYAN,
    'INFO': Fore.WHITE,
}

SEVERITY_ICONS = {
    'CRITICAL': '[!!!]',
    'HIGH': '[!! ]',
    'MEDIUM': '[!  ]',
    'LOW': '[ . ]',
    'INFO': '[   ]',
}


class TerminalReporter:

    def print_banner(self):
        print(Fore.CYAN + Style.BRIGHT + """
+--------------------------------------------------------------+
|          AI Security & Code Review Agent v1.0                |
|    OWASP - Secrets - Web - Mobile - Embedded - AI/ML          |
|              Pipeline - Cloud - Code Quality                  |
+--------------------------------------------------------------+
""")

    def print_phase(self, phase: str):
        print(Fore.CYAN + Style.BRIGHT + f"\n{'-' * 60}")
        print(Fore.CYAN + Style.BRIGHT + f"  {phase}")
        print(Fore.CYAN + Style.BRIGHT + f"{'-' * 60}")

    def print_project_info(self, info: dict):
        print(f"\n  {Fore.WHITE + Style.BRIGHT}Project:      {Style.RESET_ALL}{info['name']}")
        print(f"  {Fore.WHITE + Style.BRIGHT}Path:         {Style.RESET_ALL}{info['path']}")
        print(f"  {Fore.WHITE + Style.BRIGHT}Total Files:  {Style.RESET_ALL}{info['total_files']}")
        print(f"  {Fore.WHITE + Style.BRIGHT}Languages:    {Style.RESET_ALL}{', '.join(list(info['languages'].keys())[:5])}")
        print(f"  {Fore.WHITE + Style.BRIGHT}Frameworks:   {Style.RESET_ALL}{', '.join(info['frameworks'][:5]) or 'None detected'}")
        print(f"  {Fore.WHITE + Style.BRIGHT}Architecture: {Style.RESET_ALL}{', '.join(info['arch_types'])}")
        print(f"  {Fore.WHITE + Style.BRIGHT}Scan Domains: {Style.RESET_ALL}{', '.join(info.get('security_domains', []))}")
        skipped = info.get('skipped_domains', [])
        if skipped:
            print(f"  {Fore.WHITE + Style.BRIGHT}Skipped:      {Style.RESET_ALL}{', '.join(skipped)}")

    def print_findings_summary(self, findings: list):
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            counts[severity] = counts.get(severity, 0) + 1

        print(f"\n  {'-' * 50}")
        print(f"  {Fore.WHITE + Style.BRIGHT}SCAN SUMMARY - {len(findings)} findings{Style.RESET_ALL}")
        print(f"  {'-' * 50}")

        for severity, count in counts.items():
            if count > 0:
                color = SEVERITY_COLORS.get(severity, '')
                icon = SEVERITY_ICONS.get(severity, '')
                bar = '#' * min(count, 40)
                print(f"  {color}{icon} {severity:<10}{Style.RESET_ALL}  {color}{count:3d}  {bar}{Style.RESET_ALL}")

    def print_findings_detail(self, findings: list):
        from collections import defaultdict

        by_category = defaultdict(list)
        for finding in findings:
            by_category[finding['category']].append(finding)

        for category, cat_findings in sorted(by_category.items()):
            print(f"\n  {Fore.CYAN + Style.BRIGHT}> {category}{Style.RESET_ALL}")
            sorted_findings = sorted(
                cat_findings,
                key=lambda item: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(item['severity'], 5),
            )
            for finding in sorted_findings:
                color = SEVERITY_COLORS.get(finding['severity'], '')
                icon = SEVERITY_ICONS.get(finding['severity'], '')
                print(f"    {color}{icon} {finding['severity']:<10}{Style.RESET_ALL} {finding['name']}")
                print(f"             {Fore.WHITE}{finding['file']}:{finding['line']}{Style.RESET_ALL}")

    def print_finding_detail(self, finding: dict, current: int, total: int):
        color = SEVERITY_COLORS.get(finding['severity'], '')
        print(f"\n{'=' * 65}")
        print(f"  {color}[{current}/{total}] {finding['severity']} - {finding['name']}{Style.RESET_ALL}")
        print(f"{'=' * 65}")
        print(f"  {Fore.WHITE + Style.BRIGHT}ID:       {Style.RESET_ALL}{finding['id']}")
        print(f"  {Fore.WHITE + Style.BRIGHT}Category: {Style.RESET_ALL}{finding['category']}")
        print(f"  {Fore.WHITE + Style.BRIGHT}File:     {Style.RESET_ALL}{finding['file']}:{finding['line']}")
        if finding.get('cwe'):
            print(f"  {Fore.WHITE + Style.BRIGHT}CWE:      {Style.RESET_ALL}{finding['cwe']}")
        if finding.get('owasp'):
            print(f"  {Fore.WHITE + Style.BRIGHT}OWASP:    {Style.RESET_ALL}{finding['owasp']}")
        print(f"\n  {Fore.YELLOW}Description:{Style.RESET_ALL}")
        print(f"    {finding['description']}")
        print(f"\n  {Fore.WHITE + Style.BRIGHT}Code Context:{Style.RESET_ALL}")
        for line in finding.get('context', '').split('\n'):
            if '>>>' in line:
                print(f"    {Fore.RED}{line}{Style.RESET_ALL}")
            else:
                print(f"    {Fore.WHITE}{line}{Style.RESET_ALL}")

    def print_detailed_analysis(self, finding: dict):
        print(f"\n  {Fore.CYAN + Style.BRIGHT}Detailed Analysis:{Style.RESET_ALL}")
        print(f"    {finding['description']}")

    def print_fix_suggestions(self, finding: dict):
        print(f"\n  {Fore.GREEN + Style.BRIGHT}Fix Suggestion:{Style.RESET_ALL}")
        print(f"    {finding['fix']}")

    def print_success(self, msg: str):
        print(f"\n  {Fore.GREEN + Style.BRIGHT}[OK] {msg}{Style.RESET_ALL}")

    def print_info(self, msg: str):
        print(f"\n  {Fore.CYAN}{msg}{Style.RESET_ALL}")

    def print_error(self, msg: str):
        print(f"\n  {Fore.RED + Style.BRIGHT}[ERROR] {msg}{Style.RESET_ALL}")
