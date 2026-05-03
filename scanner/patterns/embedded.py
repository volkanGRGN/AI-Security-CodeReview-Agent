"""
Embedded Systems, IoT, Arduino, ESP32, Raspberry Pi Security Patterns.
"""

EMBEDDED_PATTERNS = [

    # ─────────────────────────────────────────────
    # HARDCODED CREDENTIALS
    # ─────────────────────────────────────────────
    {
        'id': 'EMB-001',
        'category': 'Embedded: Hardcoded Credentials',
        'name': 'Hardcoded WiFi Password',
        'severity': 'CRITICAL',
        'pattern': r'(WIFI_PASS|wifi_password|ssid_password|WiFi\.begin\s*\([^,]+,\s*["\'][^"\']{3,}["\'])',
        'description': 'WiFi password hardcoded in firmware. Extractable from binary.',
        'fix': 'Store in EEPROM/NVS after provisioning. Use WiFi provisioning (BLE/SoftAP) for setup.',
        'langs': ['.c', '.cpp', '.ino', '.h'],
    },
    {
        'id': 'EMB-002',
        'category': 'Embedded: Hardcoded Credentials',
        'name': 'Hardcoded MQTT Credentials',
        'severity': 'CRITICAL',
        'pattern': r'(mqtt_user|MQTT_USER|mqtt_pass|MQTT_PASS|mqttClient\.connect\s*\([^,]+,\s*["\'][^"\']+["\'],\s*["\'][^"\']+["\'])',
        'description': 'MQTT broker credentials hardcoded in firmware.',
        'fix': 'Store in NVS (ESP32) or EEPROM. Use mTLS certificate auth instead of passwords.',
        'langs': ['.c', '.cpp', '.ino', '.h'],
    },
    {
        'id': 'EMB-003',
        'category': 'Embedded: Hardcoded Credentials',
        'name': 'Hardcoded Admin Password',
        'severity': 'CRITICAL',
        'pattern': r'(admin_pass|ADMIN_PASSWORD|web_password|http_password)\s*[=]\s*["\'][^"\']{3,}["\']',
        'description': 'Web interface admin password hardcoded. Classic IoT vulnerability (Mirai botnet used this).',
        'fix': 'Force password change on first boot. Generate unique password from device hardware ID.',
        'langs': ['.c', '.cpp', '.ino', '.h', '.py'],
    },
    {
        'id': 'EMB-004',
        'category': 'Embedded: Hardcoded Credentials',
        'name': 'Hardcoded API Key in Firmware',
        'severity': 'CRITICAL',
        'pattern': r'(API_KEY|api_key|TOKEN|OPENAI_KEY|cloud_key)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',
        'description': 'Cloud API key hardcoded in firmware. Extractable from binary with strings command.',
        'fix': 'Provision keys securely during manufacturing or first-boot setup. Use TLS client certificates.',
        'langs': ['.c', '.cpp', '.ino', '.h', '.py'],
    },

    # ─────────────────────────────────────────────
    # COMMUNICATION SECURITY
    # ─────────────────────────────────────────────
    {
        'id': 'EMB-010',
        'category': 'Embedded: Communication',
        'name': 'Unencrypted HTTP in IoT',
        'severity': 'HIGH',
        'pattern': r'(http\.begin\s*\(["\']http://|WiFiClient\s+client|HTTPClient\s+http)',
        'negative_pattern': r'(WiFiClientSecure|HTTPSClient|https://|setInsecure)',
        'description': 'IoT device communicating over plain HTTP. Traffic sniffable on local network.',
        'fix': 'Use WiFiClientSecure with certificate verification. Implement HTTPS for all cloud communication.',
        'langs': ['.c', '.cpp', '.ino'],
    },
    {
        'id': 'EMB-011',
        'category': 'Embedded: Communication',
        'name': 'MQTT Without TLS',
        'severity': 'HIGH',
        'pattern': r'(PubSubClient\s+client|mqtt\.connect|setServer\s*\([^,]+,\s*1883\s*\))',
        'description': 'MQTT using unencrypted port 1883. All IoT messages are in plaintext.',
        'fix': 'Use MQTT over TLS on port 8883. Configure broker certificate validation.',
        'langs': ['.c', '.cpp', '.ino'],
    },
    {
        'id': 'EMB-012',
        'category': 'Embedded: Communication',
        'name': 'SSL Certificate Verification Disabled',
        'severity': 'CRITICAL',
        'pattern': r'(setInsecure\(\)|setCACert\(NULL\)|CURLOPT_SSL_VERIFYPEER.*0|verify\s*=\s*False)',
        'description': 'SSL/TLS certificate verification disabled on IoT device. MITM possible.',
        'fix': 'Pin the server certificate using setCACert(). Never use setInsecure() in production.',
        'langs': ['.c', '.cpp', '.ino', '.py'],
    },
    {
        'id': 'EMB-013',
        'category': 'Embedded: Communication',
        'name': 'Bluetooth Without Authentication',
        'severity': 'HIGH',
        'pattern': r'(BLEServer|BLECharacteristic|Bluetooth\.begin|SerialBT\.begin)',
        'negative_pattern': r'(setSecurityCallbacks|setSecurity|BLE_HS_IO_KEYBOARD|PASSKEY|bonded)',
        'description': 'Bluetooth enabled without pairing/authentication. Any device can connect.',
        'fix': 'Enable BLE bonding, set IO capabilities, require passkey pairing.',
        'langs': ['.c', '.cpp', '.ino'],
    },
    {
        'id': 'EMB-014',
        'category': 'Embedded: Communication',
        'name': 'OTA Update Without Signature Verification',
        'severity': 'CRITICAL',
        'pattern': r'(ArduinoOTA|ESP32OTA|Update\.begin|esp_ota_begin|httpUpdate)',
        'negative_pattern': r'(signature|verify|checksum|hash|sign)',
        'description': 'OTA firmware update without cryptographic signature verification. Malicious firmware installable.',
        'fix': 'Sign firmware with private key. Verify signature with embedded public key before flashing.',
        'langs': ['.c', '.cpp', '.ino'],
    },

    # ─────────────────────────────────────────────
    # DEBUG INTERFACES
    # ─────────────────────────────────────────────
    {
        'id': 'EMB-020',
        'category': 'Embedded: Debug Interfaces',
        'name': 'UART Debug Output in Production',
        'severity': 'MEDIUM',
        'pattern': r'(Serial\.print|Serial\.println|Serial\.begin\s*\(\s*\d+\s*\))',
        'description': 'UART/Serial debug output left in production firmware. Information disclosure via UART pins.',
        'fix': 'Disable Serial in release builds with #ifdef DEBUG guards.',
        'langs': ['.c', '.cpp', '.ino'],
    },
    {
        'id': 'EMB-021',
        'category': 'Embedded: Debug Interfaces',
        'name': 'JTAG/SWD Not Disabled',
        'severity': 'HIGH',
        'pattern': r'(JTAG_ENABLE|jtag_enable|SWD_ENABLE|efuse.*jtag)',
        'description': 'JTAG/SWD debug interface not explicitly disabled. Physical memory dump possible.',
        'fix': 'Burn eFuses to disable JTAG in production. Use secure boot + flash encryption (ESP32).',
        'langs': ['.c', '.cpp', '.ino'],
    },
    {
        'id': 'EMB-022',
        'category': 'Embedded: Debug Interfaces',
        'name': 'No Secure Boot',
        'severity': 'HIGH',
        'pattern': r'(esp_idf|idf_component|sdkconfig)',
        'negative_pattern': r'(CONFIG_SECURE_BOOT|secure_boot_v2|SECURE_BOOT_ENABLED)',
        'description': 'ESP32 project without secure boot configuration. Unsigned firmware can be flashed.',
        'fix': 'Enable CONFIG_SECURE_BOOT_V2_ENABLED in sdkconfig. Generate and protect signing keys.',
        'langs': ['.c', '.cpp'],
    },

    # ─────────────────────────────────────────────
    # MEMORY SAFETY
    # ─────────────────────────────────────────────
    {
        'id': 'EMB-030',
        'category': 'Embedded: Memory Safety',
        'name': 'Unsafe String Functions (Buffer Overflow)',
        'severity': 'HIGH',
        'pattern': r'\b(strcpy|strcat|sprintf|gets|scanf\s*\(\s*["\']%s)\b',
        'description': 'Unsafe C string function. Classic buffer overflow vector in embedded systems.',
        'fix': 'Use strncpy, strncat, snprintf, fgets. Always bound-check buffer operations.',
        'langs': ['.c', '.cpp', '.ino'],
    },
    {
        'id': 'EMB-031',
        'category': 'Embedded: Memory Safety',
        'name': 'malloc Without NULL Check',
        'severity': 'MEDIUM',
        'pattern': r'=\s*malloc\s*\([^;]+;(?!\s*(if|assert))',
        'description': 'malloc() result used without NULL check. Crash on memory exhaustion.',
        'fix': 'Always check: ptr = malloc(size); if(!ptr) { /* handle error */ }',
        'langs': ['.c', '.cpp', '.ino'],
    },
    {
        'id': 'EMB-032',
        'category': 'Embedded: Memory Safety',
        'name': 'Stack Buffer with User Input',
        'severity': 'HIGH',
        'pattern': r'char\s+\w+\s*\[\s*\d+\s*\].*=.*\{|char\s+buf\s*\[',
        'description': 'Fixed-size stack buffer that may receive user input. Stack overflow risk.',
        'fix': 'Validate input length before copying. Use heap allocation with size limits.',
        'langs': ['.c', '.cpp', '.ino'],
    },

    # ─────────────────────────────────────────────
    # RTOS / CONCURRENCY
    # ─────────────────────────────────────────────
    {
        'id': 'EMB-040',
        'category': 'Embedded: RTOS',
        'name': 'FreeRTOS Task Without Stack Overflow Check',
        'severity': 'MEDIUM',
        'pattern': r'xTaskCreate\s*\(',
        'negative_pattern': r'(uxTaskGetStackHighWaterMark|configCHECK_FOR_STACK_OVERFLOW)',
        'description': 'FreeRTOS task without stack overflow detection.',
        'fix': 'Enable configCHECK_FOR_STACK_OVERFLOW in FreeRTOSConfig.h and implement vApplicationStackOverflowHook.',
        'langs': ['.c', '.cpp'],
    },
    {
        'id': 'EMB-041',
        'category': 'Embedded: RTOS',
        'name': 'Mutex Not Released on Error Path',
        'severity': 'MEDIUM',
        'pattern': r'xSemaphoreTake\s*\(.*\).*\n(?!.*xSemaphoreGive)',
        'description': 'Mutex/semaphore taken but may not be released on error paths. Deadlock risk.',
        'fix': 'Use RAII wrappers or ensure semaphore is given in all exit paths including error handling.',
        'langs': ['.c', '.cpp'],
    },

    # ─────────────────────────────────────────────
    # WEARABLES / AR / VR
    # ─────────────────────────────────────────────
    {
        'id': 'EMB-050',
        'category': 'Embedded: Wearable/AR',
        'name': 'Camera/Sensor Data Without User Consent',
        'severity': 'HIGH',
        'pattern': r'(ARSession|AVCaptureSession|CameraX|camera\.open|Camera2|ARCore)',
        'negative_pattern': r'(requestPermission|checkPermission|permission\.CAMERA|NSCameraUsageDescription)',
        'description': 'Camera/AR session started without explicit permission request.',
        'fix': 'Always request and verify camera permission before starting AR sessions. Implement clear consent UI.',
        'langs': ['.swift', '.kt', '.java', '.dart', '.m'],
    },
    {
        'id': 'EMB-051',
        'category': 'Embedded: Wearable/AR',
        'name': 'Biometric/Sensor Data Transmitted Unencrypted',
        'severity': 'CRITICAL',
        'pattern': r'(heartRate|accelerometer|gyroscope|biometric|healthKit|HealthKit|CMMotionManager)',
        'negative_pattern': r'(encrypt|TLS|https|SecureChannel)',
        'description': 'Biometric or sensor data from wearable transmitted without explicit encryption.',
        'fix': 'Encrypt all biometric data at rest and in transit. Use end-to-end encryption for health data.',
        'langs': ['.swift', '.kt', '.java', '.dart'],
    },
    {
        'id': 'EMB-052',
        'category': 'Embedded: Wearable/AR',
        'name': 'Location Data Without Privacy Controls',
        'severity': 'HIGH',
        'pattern': r'(CLLocationManager|LocationServices|fusedLocationClient|LocationRequest)',
        'negative_pattern': r'(WhenInUse|coarseLocation|anonymize|aggregate)',
        'description': 'Continuous precise location access on wearable without privacy controls.',
        'fix': 'Use "when in use" permission. Anonymize/aggregate location data. Minimize precision.',
        'langs': ['.swift', '.kt', '.java', '.dart'],
    },
    {
        'id': 'EMB-053',
        'category': 'Embedded: Wearable/AR',
        'name': 'AR Scene Data Stored Without Consent',
        'severity': 'HIGH',
        'pattern': r'(ARWorldMap|saveWorldMap|ARAnchor|persistentAnchor|CloudAnchor)',
        'description': 'AR spatial mapping data saved, which contains environmental/location information.',
        'fix': 'Disclose spatial data collection to users. Do not upload AR maps without explicit consent.',
        'langs': ['.swift', '.kt', '.java'],
    },
    {
        'id': 'EMB-054',
        'category': 'Embedded: Wearable/AR',
        'name': 'Voice Assistant Data Without Encryption',
        'severity': 'HIGH',
        'pattern': r'(SFSpeechRecognizer|SpeechRecognizer|voiceInput|audioCapture|AVAudioRecorder)',
        'negative_pattern': r'(encrypt|onDevice|localModel)',
        'description': 'Voice/audio capture from smart glasses without on-device processing or encryption.',
        'fix': 'Prefer on-device speech recognition. If cloud-based, encrypt audio and disclose to users.',
        'langs': ['.swift', '.kt', '.java'],
    },
]
