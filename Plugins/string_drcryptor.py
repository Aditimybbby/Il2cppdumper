"""
String Decryption Plugin
Automatically finds and decrypts encrypted strings
"""
import re
import struct
from typing import Dict, List, Optional
from dataclasses import dataclass

from core.parser import Il2CppParser
from core.analyzer import Il2CppAnalyzer
from utils.logger import log, LogLevel

@dataclass
class DecryptedString:
    offset: int
    encrypted: bytes
    decrypted: str
    algorithm: str

class StringDecryptorPlugin:
    """Plugin for decrypting obfuscated strings"""
    
    def __init__(self, dumper):
        self.dumper = dumper
        self.name = "string_decryptor"
        self.version = "1.0"
        self.decrypted_strings: List[DecryptedString] = []
        self.string_xrefs: Dict[int, List[int]] = {}
        
        log(f"Initialized {self.name} v{self.version}", LogLevel.DEBUG)
    
    def analyze(self, parser: Il2CppParser, analyzer: Il2CppAnalyzer):
        """Analyze and decrypt strings"""
        log("Running string decryption analysis...", LogLevel.INFO)
        
        # Find string encryption patterns
        self.find_encryption_patterns(parser)
        
        # Analyze string references
        self.analyze_string_references(parser)
        
        # Try to decrypt found strings
        self.decrypt_strings(parser)
        
        log(f"Decrypted {len(self.decrypted_strings)} strings", LogLevel.SUCCESS)
    
    def find_encryption_patterns(self, parser: Il2CppParser):
        """Find patterns indicating string encryption"""
        data = parser.il2cpp_data
        
        # Common encryption patterns
        patterns = [
            # XOR patterns
            (rb"\x80[\x00-\xFF]{4}\x00\x00\x00\x80", "XOR Encryption"),
            # ROT13-like patterns
            (rb"\x41\x00\x00\x00[\x00-\xFF]{4}\x00\x00\x00\x4E", "ROT Encryption"),
            # Base64 patterns
            (rb"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "Base64"),
        ]
        
        for pattern, algo in patterns:
            matches = list(re.finditer(pattern, data))
            if matches:
                log(f"Found {len(matches)} {algo} patterns", LogLevel.INFO)
    
    def analyze_string_references(self, parser: Il2CppParser):
        """Find code that references encrypted strings"""
        # Look for common string decryption function patterns
        decryption_func_patterns = [
            b"DecryptString", b"DecodeString", b"Deobfuscate",
            b"xor_decrypt", b"decrypt", b"Decrypt"
        ]
        
        for i, method in enumerate(parser.metadata.methods[:1000]):  # First 1000
            method_name = parser.get_string(method.name_index)
            if any(pattern.decode() in method_name for pattern in decryption_func_patterns):
                log(f"Found potential decryption function: {method_name}", LogLevel.DEBUG)
    
    def decrypt_strings(self, parser: Il2CppParser):
        """Attempt to decrypt found strings"""
        # This is a simplified example
        # Real implementation would:
        # 1. Find decryption functions
        # 2. Emulate/execute them
        # 3. Apply to encrypted strings
        
        # Example: Simple XOR decryption
        for i in range(min(100, len(parser.metadata.strings))):
            string = parser.metadata.strings[i]
            if self.looks_encrypted(string):
                try:
                    decrypted = self.try_xor_decrypt(string)
                    if decrypted != string:
                        self.decrypted_strings.append(
                            DecryptedString(i, string.encode(), decrypted, "XOR")
                        )
                except:
                    pass
    
    def looks_encrypted(self, string: str) -> bool:
        """Check if string looks encrypted"""
        if not string:
            return False
        
        # Encrypted strings often have non-printable characters
        for char in string:
            if ord(char) < 32 and char not in '\n\r\t':
                return True
        
        # Or have unusual character distribution
        return False
    
    def try_xor_decrypt(self, encrypted: str, key: int = 0x55) -> str:
        """Try XOR decryption with given key"""
        result = []
        for char in encrypted:
            result.append(chr(ord(char) ^ key))
        return ''.join(result)
    
    def generate_report(self) -> str:
        """Generate decryption report"""
        report = ["String Decryption Report", "=" * 40]
        
        for decrypted in self.decrypted_strings[:50]:  # First 50
            report.append(f"Offset: 0x{decrypted.offset:X}")
            report.append(f"  Encrypted: {decrypted.encrypted[:50]}...")
            report.append(f"  Decrypted: {decrypted.decrypted[:50]}...")
            report.append(f"  Algorithm: {decrypted.algorithm}")
            report.append("")
        
        return '\n'.join(report)

# Plugin entry point
Plugin = StringDecryptorPlugin
