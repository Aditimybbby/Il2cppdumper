"""
Il2Cpp Runtime Hooking System
Hook into running Unity games
"""
import ctypes
import sys
import os
from typing import Dict, List, Callable, Any
from dataclasses import dataclass
from enum import Enum

# Platform-specific imports
if sys.platform == 'win32':
    import win32api
    import win32process
elif sys.platform == 'linux':
    import ptrace
elif sys.platform == 'darwin':
    # macOS
    pass

class HookType(Enum):
    DETOUR = 1      # Redirect function
    INLINE = 2      # Modify code in-place
    VTABLE = 3      # Modify virtual table
    IAT = 4         # Import Address Table hook

@dataclass
class Hook:
    name: str
    target_address: int
    hook_function: Callable
    original_bytes: bytes
    hook_type: HookType
    enabled: bool = False

class Il2CppHookManager:
    """Manage runtime hooks for Il2Cpp games"""
    
    def __init__(self):
        self.hooks: Dict[str, Hook] = {}
        self.process_handle = None
        self.process_id = 0
        self.base_address = 0
        
        print("[HOOK] Il2Cpp Hook Manager initialized")
    
    def attach_to_process(self, process_name: str) -> bool:
        """Attach to running game process"""
        try:
            if sys.platform == 'win32':
                return self._attach_windows(process_name)
            elif sys.platform == 'linux':
                return self._attach_linux(process_name)
            else:
                print(f"[HOOK] Platform {sys.platform} not supported")
                return False
        except Exception as e:
            print(f"[HOOK] Failed to attach: {e}")
            return False
    
    def _attach_windows(self, process_name: str) -> bool:
        """Attach on Windows"""
        import win32process
        import win32api
        
        # Find process by name
        processes = win32process.EnumProcesses()
        for pid in processes:
            try:
                hProcess = win32api.OpenProcess(0x0400, False, pid)
                exe_name = win32process.GetModuleFileNameEx(hProcess, 0)
                if process_name.lower() in exe_name.lower():
                    self.process_id = pid
                    self.process_handle = hProcess
                    
                    # Get base address
                    modules = win32process.EnumProcessModules(hProcess)
                    if modules:
                        self.base_address = modules[0]
                    
                    print(f"[HOOK] Attached to PID {pid}, base: 0x{self.base_address:X}")
                    return True
            except:
                continue
        
        return False
    
    def install_hook(self, name: str, target_address: int, 
                    hook_function: Callable, hook_type: HookType = HookType.DETOUR) -> bool:
        """Install a hook at specified address"""
        try:
            # Save original bytes
            original_bytes = self.read_memory(target_address, 20)
            
            # Create hook
            hook = Hook(
                name=name,
                target_address=target_address,
                hook_function=hook_function,
                original_bytes=original_bytes,
                hook_type=hook_type
            )
            
            # Install based on type
            if hook_type == HookType.DETOUR:
                self._install_detour_hook(hook)
            elif hook_type == HookType.INLINE:
                self._install_inline_hook(hook)
            
            self.hooks[name] = hook
            hook.enabled = True
            
            print(f"[HOOK] Installed hook '{name}' at 0x{target_address:X}")
            return True
            
        except Exception as e:
            print(f"[HOOK] Failed to install hook '{name}': {e}")
            return False
    
    def _install_detour_hook(self, hook: Hook):
        """Install detour hook (jump to our function)"""
        # x86_64: JMP [rip+0] ; address
        if sys.platform == 'win32':
            # Windows x64: FF 25 00000000 [address]
            jmp_code = b"\xFF\x25\x00\x00\x00\x00" + hook.target_address.to_bytes(8, 'little')
        else:
            # Linux x64: same
            jmp_code = b"\xFF\x25\x00\x00\x00\x00" + hook.target_address.to_bytes(8, 'little')
        
        self.write_memory(hook.target_address, jmp_code)
    
    def _install_inline_hook(self, hook: Hook):
        """Install inline hook (modify beginning of function)"""
        # Simple NOP sled for demonstration
        nop_sled = b"\x90" * 10  # 10 NOPs
        self.write_memory(hook.target_address, nop_sled)
    
    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from target process"""
        if not self.process_handle:
            return b""
        
        if sys.platform == 'win32':
            import win32api
            win32process.ReadProcessMemory(self.process_handle, address, size)
        else:
            # Linux/Mac implementation
            pass
        
        # Simplified return
        return b"\x00" * size
    
    def write_memory(self, address: int, data: bytes):
        """Write memory to target process"""
        if not self.process_handle:
            return
        
        if sys.platform == 'win32':
            import win32process
            win32process.WriteProcessMemory(self.process_handle, address, data)
        else:
            # Linux/Mac
            pass
    
    def hook_common_functions(self, parser):
        """Hook common Il2Cpp functions automatically"""
        print("[HOOK] Installing common Il2Cpp hooks...")
        
        # Hook string functions
        string_hooks = [
            ("il2cpp_string_new", self.hook_string_new),
            ("il2cpp_string_new_len", self.hook_string_new_len),
        ]
        
        for func_name, hook_func in string_hooks:
            # Find function in parser
            for method in parser.metadata.methods:
                method_name = parser.get_string(method.name_index)
                if func_name in method_name and method.address:
                    self.install_hook(
                        name=f"hook_{func_name}",
                        target_address=method.address,
                        hook_function=hook_func
                    )
                    break
    
    def hook_string_new(self, original_str: str) -> str:
        """Hook for il2cpp_string_new"""
        print(f"[HOOK] il2cpp_string_new called with: {original_str[:50]}...")
        # Modify string if needed
        if "score" in original_str.lower():
            return "HACKED_SCORE"
        return original_str
    
    def hook_string_new_len(self, original_str: str, length: int) -> str:
        """Hook for il2cpp_string_new_len"""
        print(f"[HOOK] il2cpp_string_new_len: {original_str[:50]}..., len: {length}")
        return original_str
    
    def create_cheat_hooks(self):
        """Create common cheat hooks"""
        print("[HOOK] Creating cheat hooks...")
        
        # Example: God mode hook
        god_mode_hook = Hook(
            name="god_mode",
            target_address=0xDEADBEEF,  # Would be actual address
            hook_function=self.god_mode_hook,
            original_bytes=b"",
            hook_type=HookType.INLINE
        )
        
        self.hooks["god_mode"] = god_mode_hook
    
    def god_mode_hook(self, player_ptr: int):
        """God mode hook function"""
        # This would modify player health
        print(f"[HOOK] God mode triggered for player: 0x{player_ptr:X}")
        
        # Write max health
        health_offset = 0x40  # Example offset
        max_health = 9999
        
        health_addr = player_ptr + health_offset
        self.write_memory(health_addr, max_health.to_bytes(4, 'little'))
    
    def enable_all_hooks(self):
        """Enable all installed hooks"""
        for hook in self.hooks.values():
            hook.enabled = True
        print(f"[HOOK] Enabled {len(self.hooks)} hooks")
    
    def disable_all_hooks(self):
        """Disable all hooks"""
        for hook in self.hooks.values():
            hook.enabled = False
        print(f"[HOOK] Disabled all hooks")
