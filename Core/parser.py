"""
Advanced Il2Cpp Parser with extensible architecture
"""
import struct
import mmap
import os
from typing import BinaryIO, List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import IntFlag, IntEnum

from .structures import *
from utils.logger import log, LogLevel

class ParseMode(IntFlag):
    BASIC = 0
    DEEP = 1
    WITH_METHOD_BODIES = 2
    WITH_FIELD_VALUES = 4
    WITH_ATTRIBUTES = 8

class Il2CppParser:
    def __init__(self, il2cpp_path: str, metadata_path: str, 
                 mode: ParseMode = ParseMode.DEEP, extract_method_bodies: bool = False):
        self.il2cpp_path = il2cpp_path
        self.metadata_path = metadata_path
        self.mode = mode
        self.extract_method_bodies = extract_method_bodies
        
        self.il2cpp_data: Optional[mmap.mmap] = None
        self.metadata_data: Optional[mmap.mmap] = None
        self.metadata: Optional[Metadata] = None
        
        # Caches for performance
        self._string_cache: Dict[int, str] = {}
        self._type_cache: Dict[int, TypeDefinition] = {}
        self._method_cache: Dict[int, MethodDefinition] = {}
        
        # Analysis results
        self.code_registration: Optional[CodeRegistration] = None
        self.metadata_registration: Optional[MetadataRegistration] = None
        self.symbols: Dict[str, int] = {}
        
        log(f"Parser initialized with mode: {mode}", LogLevel.DEBUG)
    
    def load(self) -> bool:
        """Memory-map files for fast access"""
        try:
            # Map il2cpp binary
            il2cpp_file = open(self.il2cpp_path, 'rb')
            self.il2cpp_data = mmap.mmap(il2cpp_file.fileno(), 0, access=mmap.ACCESS_READ)
            
            # Map metadata
            metadata_file = open(self.metadata_path, 'rb')
            self.metadata_data = mmap.mmap(metadata_file.fileno(), 0, access=mmap.ACCESS_READ)
            
            # Parse metadata header
            if not self.parse_metadata_header():
                return False
            
            # Find Il2Cpp structures in binary
            self.find_il2cpp_structures()
            
            # Parse all metadata
            self.parse_all_metadata()
            
            log(f"Successfully loaded {os.path.basename(self.il2cpp_path)}", LogLevel.SUCCESS)
            return True
            
        except Exception as e:
            log(f"Failed to load files: {e}", LogLevel.ERROR)
            return False
    
    def parse_metadata_header(self) -> bool:
        """Parse global-metadata.dat header"""
        try:
            data = self.metadata_data
            
            # Read 32 uint32 values
            values = struct.unpack_from('I' * 32, data, 0)
            
            if values[0] != 0xFAB11BAF:  # Sanity check
                log(f"Invalid metadata magic: 0x{values[0]:X}", LogLevel.ERROR)
                return False
            
            self.metadata = Metadata(
                sanity=values[0],
                version=values[1],
                string_literal_offset=values[2],
                string_literal_count=values[3],
                string_literal_data_offset=values[4],
                string_literal_data_count=values[5],
                string_offset=values[6],
                string_count=values[7],
                events_offset=values[8],
                events_count=values[9],
                properties_offset=values[10],
                properties_count=values[11],
                methods_offset=values[12],
                methods_count=values[13],
                parameter_default_values_offset=values[14],
                parameter_default_values_count=values[15],
                field_default_values_offset=values[16],
                field_default_values_count=values[17],
                field_and_parameter_default_value_data_offset=values[18],
                field_and_parameter_default_value_data_count=values[19],
                type_definitions_offset=values[20],
                type_definitions_count=values[21],
                images_offset=values[22],
                images_count=values[23],
                assemblies_offset=values[24],
                assemblies_count=values[25],
                metadata_usage_lists_offset=values[26],
                metadata_usage_lists_count=values[27],
                metadata_usage_pairs_offset=values[28],
                metadata_usage_pairs_count=values[29],
                field_refs_offset=values[30],
                field_refs_count=values[31]
            )
            
            log(f"Metadata v{self.metadata.version} loaded", LogLevel.INFO)
            log(f"  Types: {self.metadata.type_definitions_count}", LogLevel.DEBUG)
            log(f"  Methods: {self.metadata.methods_count}", LogLevel.DEBUG)
            log(f"  Strings: {self.metadata.string_count}", LogLevel.DEBUG)
            
            return True
            
        except Exception as e:
            log(f"Failed to parse metadata header: {e}", LogLevel.ERROR)
            return False
    
    def parse_all_metadata(self):
        """Parse all metadata structures"""
        if not self.metadata:
            return
        
        log("Parsing metadata...", LogLevel.INFO)
        
        # Parse strings
        self.parse_strings()
        
        # Parse types
        self.parse_types()
        
        # Parse methods
        self.parse_methods()
        
        # Parse fields
        self.parse_fields()
        
        # Parse images and assemblies
        self.parse_images()
        self.parse_assemblies()
        
        log("Metadata parsing completed", LogLevel.SUCCESS)
    
    def parse_strings(self):
        """Parse string table with caching"""
        offset = self.metadata.string_offset
        count = self.metadata.string_count
        
        string_offsets = struct.unpack_from(f'I' * count, self.metadata_data, offset)
        
        self.metadata.strings = []
        for i in range(count):
            str_offset = string_offsets[i]
            end = self.metadata_data.find(b'\x00', str_offset)
            if end != -1:
                string = self.metadata_data[str_offset:end].decode('utf-8', errors='ignore')
            else:
                string = f"STRING_{i}"
            
            self.metadata.strings.append(string)
            self._string_cache[i] = string
    
    def parse_types(self):
        """Parse all type definitions"""
        offset = self.metadata.type_definitions_offset
        count = self.metadata.type_definitions_count
        
        # TypeDefinition is 24 uint32 values
        type_size = 24 * 4
        
        self.metadata.types = []
        for i in range(count):
            type_offset = offset + (i * type_size)
            values = struct.unpack_from('I' * 24, self.metadata_data, type_offset)
            
            type_def = TypeDefinition(
                name_index=values[0],
                namespace_index=values[1],
                byval_type_index=values[2],
                byref_type_index=values[3],
                declaring_type_index=values[4],
                parent_index=values[5],
                element_type_index=values[6],
                generic_container_index=values[7],
                flags=values[8],
                field_start=values[9],
                method_start=values[10],
                event_start=values[11],
                property_start=values[12],
                nested_types_start=values[13],
                interfaces_start=values[14],
                vtable_start=values[15],
                interface_offsets_start=values[16],
                method_count=values[17],
                property_count=values[18],
                field_count=values[19],
                event_count=values[20],
                nested_type_count=values[21],
                vtable_count=values[22],
                interfaces_count=values[23],
                interface_offsets_count=values[24] if len(values) > 24 else 0
            )
            
            self.metadata.types.append(type_def)
            self._type_cache[i] = type_def
    
    def parse_methods(self):
        """Parse all method definitions with optional body extraction"""
        offset = self.metadata.methods_offset
        count = self.metadata.methods_count
        
        # MethodDefinition is 13 uint32 values
        method_size = 13 * 4
        
        self.metadata.methods = []
        for i in range(count):
            method_offset = offset + (i * method_size)
            values = struct.unpack_from('I' * 13, self.metadata_data, method_offset)
            
            method_def = MethodDefinition(
                name_index=values[0],
                declaring_type_index=values[1],
                return_type_index=values[2],
                parameter_start=values[3],
                generic_container_index=values[4],
                method_index=values[5],
                invoker_index=values[6],
                delegate_wrapper_index=values[7],
                rgctx_start_index=values[8],
                flags=values[9],
                iflags=values[10],
                slot=values[11],
                parameter_count=values[12],
                address=0  # Will be filled later
            )
            
            # Try to get method address if code registration is found
            if self.code_registration and i < self.code_registration.method_pointers_count:
                addr_offset = self.code_registration.method_pointers + (i * 8)
                method_def.address = struct.unpack_from('Q', self.il2cpp_data, addr_offset)[0]
            
            self.metadata.methods.append(method_def)
            self._method_cache[i] = method_def
            
            # Extract method body if enabled
            if self.extract_method_bodies and method_def.address:
                self.extract_method_body(method_def)
    
    def extract_method_body(self, method: MethodDefinition):
        """Extract and disassemble method body"""
        try:
            # This is simplified - real implementation would disassemble
            pass
        except Exception as e:
            log(f"Failed to extract method body: {e}", LogLevel.DEBUG)
    
    def parse_fields(self):
        """Parse field definitions"""
        # Field parsing is version-dependent
        # Simplified implementation
        self.metadata.fields = []
        
        # Try to find field definitions
        # In real implementation, this would parse based on metadata version
        
        log(f"Field parsing simplified in this version", LogLevel.WARNING)
    
    def parse_images(self):
        """Parse image definitions"""
        offset = self.metadata.images_offset
        count = self.metadata.images_count
        
        # ImageDefinition is 4 uint32 values
        image_size = 4 * 4
        
        self.metadata.images = []
        for i in range(count):
            image_offset = offset + (i * image_size)
            values = struct.unpack_from('I' * 4, self.metadata_data, image_offset)
            
            image = ImageDefinition(
                name_index=values[0],
                assembly_index=values[1],
                type_start=values[2],
                type_count=values[3]
            )
            self.metadata.images.append(image)
    
    def parse_assemblies(self):
        """Parse assembly definitions"""
        offset = self.metadata.assemblies_offset
        count = self.metadata.assemblies_count
        
        # AssemblyDefinition is 1 uint32 value (name index)
        self.metadata.assemblies = []
        for i in range(count):
            name_index = struct.unpack_from('I', self.metadata_data, offset + (i * 4))[0]
            self.metadata.assemblies.append(name_index)
    
    def find_il2cpp_structures(self):
        """Find Il2Cpp structures in binary using multiple methods"""
        log("Scanning for Il2Cpp structures...", LogLevel.INFO)
        
        # Method 1: Search for header
        self.scan_for_header()
        
        # Method 2: Search for symbols
        self.scan_for_symbols()
        
        # Method 3: Pattern matching
        self.pattern_scan()
        
        if self.code_registration:
            log(f"Found CodeRegistration with {self.code_registration.method_pointers_count} methods", LogLevel.SUCCESS)
        else:
            log("Could not find Il2Cpp structures, using metadata only", LogLevel.WARNING)
    
    def scan_for_header(self):
        """Scan for Il2Cpp binary header"""
        data = self.il2cpp_data
        
        # Search for "asm\0" magic
        for i in range(0, len(data) - 4, 4):
            if data[i:i+4] == b'asm\0':
                try:
                    # Parse Il2CppBinaryHeader
                    values = struct.unpack_from('I' * 9, data, i)
                    header = Il2CppBinaryHeader(*values)
                    
                    log(f"Found Il2Cpp header at 0x{i:X}, version: {header.version}", LogLevel.INFO)
                    
                    # Calculate addresses
                    base_addr = 0  # Would be actual base in memory
                    self.code_registration = CodeRegistration(
                        method_pointers_count=header.method_count,
                        method_pointers=base_addr + header.code_registration_offset
                    )
                    
                    break
                except:
                    continue
    
    def scan_for_symbols(self):
        """Scan for ELF/PE symbols"""
        if self.is_elf():
            self.scan_elf_symbols()
        elif self.is_pe():
            self.scan_pe_symbols()
    
    def is_elf(self) -> bool:
        """Check if file is ELF format"""
        return self.il2cpp_data[:4] == b'\x7fELF'
    
    def is_pe(self) -> bool:
        """Check if file is PE format (Windows)"""
        return self.il2cpp_data[:2] == b'MZ'
    
    def scan_elf_symbols(self):
        """Scan ELF symbol table"""
        # Simplified ELF parsing
        # Real implementation would parse ELF sections
        
        common_symbols = [
            b"g_CodeRegistration",
            b"g_MetadataRegistration",
            b"il2cpp_codegen_register",
            b"s_Il2CppCodeRegistration"
        ]
        
        for symbol in common_symbols:
            pos = self.il2cpp_data.find(symbol)
            if pos != -1:
                self.symbols[symbol.decode()] = pos
                log(f"Found symbol: {symbol.decode()}", LogLevel.DEBUG)
    
    def scan_pe_symbols(self):
        """Scan PE export table (Windows)"""
        # Would parse PE headers and export directory
        pass
    
    def pattern_scan(self):
        """Pattern scan for Il2Cpp structures"""
        patterns = [
            # Pattern for CodeRegistration
            (b"\x00\x00\x00\x00....\x00\x00\x00\x00", "CodeRegistration"),
            # Pattern for method pointers
            (b"\x48\x8B\x05....\x48\x85\xC0\x74", "MethodTable"),
        ]
        
        for pattern, name in patterns:
            # Simple pattern scanning
            # Real implementation would use proper pattern matching
            pass
    
    def get_string(self, index: int) -> str:
        """Get string by index with caching"""
        if index in self._string_cache:
            return self._string_cache[index]
        
        if 0 <= index < len(self.metadata.strings):
            return self.metadata.strings[index]
        
        return f"STRING_{index}"
    
    def get_type(self, index: int) -> Optional[TypeDefinition]:
        """Get type by index"""
        if index in self._type_cache:
            return self._type_cache[index]
        return None
    
    def get_method(self, index: int) -> Optional[MethodDefinition]:
        """Get method by index"""
        if index in self._method_cache:
            return self._method_cache[index]
        return None
    
    def find_method_by_name(self, name: str) -> List[MethodDefinition]:
        """Find all methods with given name"""
        results = []
        for method in self.metadata.methods:
            if self.get_string(method.name_index) == name:
                results.append(method)
        return results
    
    def find_type_by_name(self, name: str) -> List[TypeDefinition]:
        """Find all types with given name"""
        results = []
        for type_def in self.metadata.types:
            if self.get_string(type_def.name_index) == name:
                results.append(type_def)
        return results
    
    def close(self):
        """Clean up resources"""
        if self.il2cpp_data:
            self.il2cpp_data.close()
        if self.metadata_data:
            self.metadata_data.close()
