"""
Architecture & Technology Detector
Identifies project type, languages, frameworks, and target platform.
"""

import os
from pathlib import Path
from collections import Counter


# File extension → language mapping
LANG_MAP = {
    '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
    '.jsx': 'React', '.tsx': 'React/TS', '.java': 'Java',
    '.kt': 'Kotlin', '.swift': 'Swift', '.c': 'C', '.cpp': 'C++',
    '.h': 'C/C++ Header', '.rs': 'Rust', '.go': 'Go',
    '.rb': 'Ruby', '.php': 'PHP', '.cs': 'C#', '.dart': 'Dart',
    '.sol': 'Solidity', '.m': 'Objective-C', '.ino': 'Arduino',
    '.sh': 'Shell', '.yaml': 'YAML', '.yml': 'YAML',
    '.json': 'JSON', '.toml': 'TOML', '.tf': 'Terraform',
    '.gradle': 'Gradle', '.xml': 'XML', '.html': 'HTML', '.css': 'CSS',
}

# Config files that reveal framework/platform
FRAMEWORK_SIGNALS = {
    # Web frameworks
    'package.json':         'Node.js',
    'next.config.js':       'Next.js',
    'next.config.ts':       'Next.js',
    'nuxt.config.js':       'Nuxt.js',
    'angular.json':         'Angular',
    'vue.config.js':        'Vue.js',
    'svelte.config.js':     'Svelte',
    'remix.config.js':      'Remix',
    'astro.config.mjs':     'Astro',
    'requirements.txt':     'Python',
    'Pipfile':              'Python/Pipenv',
    'pyproject.toml':       'Python',
    'setup.py':             'Python Package',
    'manage.py':            'Django',
    'wsgi.py':              'Django/Flask/WSGI',
    'asgi.py':              'Django/ASGI',
    'app.py':               'Flask/FastAPI',
    'main.py':              'Python App',
    'Gemfile':              'Ruby/Rails',
    'pom.xml':              'Java/Maven',
    'build.gradle':         'Java/Gradle',
    'build.gradle.kts':     'Kotlin/Gradle',
    'go.mod':               'Go Module',
    'Cargo.toml':           'Rust',
    'composer.json':        'PHP/Composer',
    'pubspec.yaml':         'Flutter/Dart',
    # Mobile
    'AndroidManifest.xml':  'Android',
    'Info.plist':           'iOS',
    'Podfile':              'iOS/CocoaPods',
    'Podfile.lock':         'iOS/CocoaPods',
    'build.gradle':         'Android/Gradle',
    'google-services.json': 'Android/Firebase',
    'GoogleService-Info.plist': 'iOS/Firebase',
    # Embedded / IoT
    'platformio.ini':       'PlatformIO/Embedded',
    'CMakeLists.txt':       'CMake/Embedded',
    'Makefile':             'C/C++ Build',
    'sdkconfig':            'ESP-IDF',
    'idf_component.yml':    'ESP-IDF',
    'sketch.yaml':          'Arduino',
    # AI / ML
    'model.py':             'ML Model',
    'train.py':             'ML Training',
    'inference.py':         'ML Inference',
    'config.yaml':          'ML Config',
    'environment.yml':      'Conda/ML',
    'mlflow.yaml':          'MLflow',
    # CI/CD & Infrastructure
    '.github':              'GitHub Actions',
    'Dockerfile':           'Docker',
    'docker-compose.yml':   'Docker Compose',
    'docker-compose.yaml':  'Docker Compose',
    '.gitlab-ci.yml':       'GitLab CI',
    'Jenkinsfile':          'Jenkins',
    '.travis.yml':          'Travis CI',
    'circle.yml':           'CircleCI',
    '.circleci':            'CircleCI',
    'k8s':                  'Kubernetes',
    'kubernetes':           'Kubernetes',
    'helm':                 'Helm/K8s',
    'terraform':            'Terraform',
    'main.tf':              'Terraform',
    'serverless.yml':       'Serverless Framework',
    'template.yaml':        'AWS SAM',
    'samconfig.toml':       'AWS SAM',
    # Blockchain
    'hardhat.config.js':    'Hardhat/Solidity',
    'truffle-config.js':    'Truffle/Solidity',
    'foundry.toml':         'Foundry/Solidity',
}

# Architecture type detection rules
ARCH_SIGNALS = {
    'android':    ['AndroidManifest.xml', 'build.gradle', 'google-services.json', '.kt', '.java'],
    'ios':        ['Info.plist', 'Podfile', '.swift', '.m', 'xcodeproj', 'xcworkspace'],
    'flutter':    ['pubspec.yaml', '.dart', 'lib/main.dart'],
    'embedded':   ['platformio.ini', 'CMakeLists.txt', '.ino', 'sdkconfig', 'idf_component.yml', 'sketch.yaml'],
    'ai_ml':      ['model.py', 'train.py', 'inference.py', 'environment.yml', 'mlflow.yaml', '.ipynb'],
    'blockchain': ['hardhat.config.js', 'truffle-config.js', '.sol', 'foundry.toml'],
    'devops':     ['Dockerfile', 'docker-compose.yml', 'Jenkinsfile', '.gitlab-ci.yml', 'main.tf'],
    'web':        ['package.json', 'manage.py', 'app.py', 'pom.xml', 'go.mod', 'Cargo.toml'],
    'desktop':    ['electron.js', 'tauri.conf.json', 'main.rs', '.exe', '.dmg'],
    'wearable':   ['watchos', 'watch_app', 'wearable', 'glasses', 'ar_session', 'ARSession', 'VisionOS'],
}

SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.pytest_cache', 'venv', 'env',
    '.env', 'dist', 'build', 'target', '.gradle', '.idea', '.vscode',
    'vendor', 'Pods', '.dart_tool', '.pub-cache', 'coverage',
    'htmlcov', 'eggs', '.eggs', 'site-packages', '.tox',
}

MAX_FILES_SCAN = 2000


class ProjectDetector:
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.all_files = []
        self.detected_frameworks = []
        self.lang_counts = Counter()
        self.arch_types = []

    def detect(self) -> dict:
        self._walk()
        self._detect_languages()
        self._detect_frameworks()
        self._detect_architecture()
        return {
            'path': str(self.repo_path),
            'name': self.repo_path.name,
            'languages': dict(self.lang_counts.most_common(10)),
            'primary_language': self.lang_counts.most_common(1)[0][0] if self.lang_counts else 'Unknown',
            'frameworks': self.detected_frameworks,
            'arch_types': self.arch_types,
            'total_files': len(self.all_files),
            'file_list': self.all_files,
        }

    def _walk(self):
        count = 0
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]
            for f in files:
                if count >= MAX_FILES_SCAN:
                    break
                full = Path(root) / f
                self.all_files.append(full)
                count += 1

    def _detect_languages(self):
        for f in self.all_files:
            ext = f.suffix.lower()
            lang = LANG_MAP.get(ext)
            if lang:
                self.lang_counts[lang] += 1

    def _detect_frameworks(self):
        all_names = {f.name for f in self.all_files}
        all_names_lower = {f.name.lower() for f in self.all_files}
        all_dirs = {str(f.parent).lower() for f in self.all_files}

        for signal, framework in FRAMEWORK_SIGNALS.items():
            if signal in all_names or signal in all_names_lower:
                if framework not in self.detected_frameworks:
                    self.detected_frameworks.append(framework)

        # Check directory names
        for d in all_dirs:
            if 'kubernetes' in d or '/k8s' in d:
                if 'Kubernetes' not in self.detected_frameworks:
                    self.detected_frameworks.append('Kubernetes')
            if 'terraform' in d:
                if 'Terraform' not in self.detected_frameworks:
                    self.detected_frameworks.append('Terraform')
            if 'helm' in d:
                if 'Helm' not in self.detected_frameworks:
                    self.detected_frameworks.append('Helm')

    def _detect_architecture(self):
        all_names = {f.name for f in self.all_files}
        all_paths_str = ' '.join(str(f).lower() for f in self.all_files)

        for arch, signals in ARCH_SIGNALS.items():
            for signal in signals:
                if signal in all_names or signal.lower() in all_paths_str:
                    if arch not in self.arch_types:
                        self.arch_types.append(arch)
                    break

        # Wearable / AR / VR detection via content signals
        wearable_keywords = [
            'arkit', 'arcore', 'visionos', 'watchkit', 'watchos',
            'glasses', 'rayban', 'meta_glasses', 'ar_session',
            'spatial_computing', 'hololens', 'openvr', 'openxr'
        ]
        for kw in wearable_keywords:
            if kw in all_paths_str:
                if 'wearable' not in self.arch_types:
                    self.arch_types.append('wearable')
                break

        # If nothing detected, default to 'web'
        if not self.arch_types:
            self.arch_types = ['web']
