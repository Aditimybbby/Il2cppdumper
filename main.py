#!/usr/bin/env python3
"""
Advanced Il2Cpp Dumper Framework v4.0
Extensible, Plugin-based, with Runtime Hooking
"""
import argparse
import sys
import os
import yaml
import importlib
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add core to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.parser import Il2CppParser
from core.analyzer import Il2CppAnalyzer
from core.hooks import HookManager
from utils.logger import setup_logger, log, LogLevel
from outputs.cs_generator import CSDumpGenerator
from outputs.json_exporter import JSONExporter
from outputs.ida_script import IDAScriptGenerator

class AdvancedIl2CppDumper:
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self.load_config(config_path)
        self.parser: Optional[Il2CppParser] = None
        self.analyzer: Optional[Il2CppAnalyzer] = None
        self.hook_manager: Optional[HookManager] = None
        self.plugins: Dict[str, Any] = {}
        self.output_generators: Dict[str, Any] = {}
        
        # Setup logging
        log_level = LogLevel[self.config.get('logging', {}).get('level', 'INFO')]
        setup_logger(log_level)
        
        log("Advanced Il2Cpp Dumper Framework v4.0", LogLevel.INFO)
        log("=" * 60, LogLevel.INFO)
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML"""
        default_config = {
            'logging': {'level': 'INFO', 'file': 'dumper.log'},
            'plugins': {
                'enabled': ['string_decryptor', 'obfuscation_detector', 'sdk_generator'],
                'auto_load': True
            },
            'analysis': {
                'deep_scan': True,
                'find_string_references': True,
                'detect_encryption': True,
                'extract_method_bodies': False
            },
            'output': {
                'formats': ['cs', 'json', 'ida_python', 'cheat_engine'],
                'include_offsets': True,
                'include_strings': True,
                'generate_sdk': True
            },
            'hooking': {
                'enable': False,
                'target_process': None,
                'inject_dll': False
            }
        }
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                # Merge with defaults
                default_config.update(user_config)
        
        return default_config
    
    def load_plugins(self):
        """Dynamically load all enabled plugins"""
        log("Loading plugins...", LogLevel.INFO)
        
        plugin_dir = Path("plugins")
        enabled_plugins = self.config['plugins']['enabled']
        
        for plugin_name in enabled_plugins:
            try:
                plugin_path = plugin_dir / f"{plugin_name}.py"
                if plugin_path.exists():
                    # Dynamic import
                    spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
                    plugin_module = importlib.util.module_from_spec(spec)
                    sys.modules[plugin_name] = plugin_module
                    spec.loader.exec_module(plugin_module)
                    
                    # Initialize plugin
                    if hasattr(plugin_module, 'Plugin'):
                        plugin_instance = plugin_module.Plugin(self)
                        self.plugins[plugin_name] = plugin_instance
                        log(f"✓ Loaded plugin: {plugin_name}", LogLevel.SUCCESS)
                    
            except Exception as e:
                log(f"✗ Failed to load plugin {plugin_name}: {e}", LogLevel.ERROR)
    
    def initialize_parser(self, il2cpp_path: str, metadata_path: str):
        """Initialize Il2Cpp parser with advanced options"""
        log(f"Initializing parser...", LogLevel.INFO)
        log(f"  Il2Cpp: {il2cpp_path}", LogLevel.DEBUG)
        log(f"  Metadata: {metadata_path}", LogLevel.DEBUG)
        
        self.parser = Il2CppParser(
            il2cpp_path=il2cpp_path,
            metadata_path=metadata_path,
            deep_scan=self.config['analysis']['deep_scan'],
            extract_method_bodies=self.config['analysis']['extract_method_bodies']
        )
        
        if not self.parser.load():
            log("Failed to load Il2Cpp files!", LogLevel.ERROR)
            return False
        
        log(f"✓ Loaded {len(self.parser.metadata.strings)} strings", LogLevel.SUCCESS)
        log(f"✓ Loaded {len(self.parser.metadata.types)} types", LogLevel.SUCCESS)
        log(f"✓ Loaded {len(self.parser.metadata.methods)} methods", LogLevel.SUCCESS)
        
        return True
    
    def run_analysis(self):
        """Run complete analysis with all plugins"""
        if not self.parser:
            log("Parser not initialized!", LogLevel.ERROR)
            return
        
        log("Starting analysis...", LogLevel.INFO)
        
        # Initialize analyzer
        self.analyzer = Il2CppAnalyzer(self.parser)
        
        # Run core analysis
        self.analyzer.analyze_string_references()
        self.analyzer.analyze_type_hierarchy()
        self.analyzer.analyze_method_patterns()
        
        # Run plugin analysis
        for plugin_name, plugin in self.plugins.items():
            log(f"Running plugin: {plugin_name}", LogLevel.DEBUG)
            try:
                plugin.analyze(self.parser, self.analyzer)
            except Exception as e:
                log(f"Plugin {plugin_name} failed: {e}", LogLevel.ERROR)
        
        log("✓ Analysis completed", LogLevel.SUCCESS)
    
    def generate_outputs(self, output_dir: str):
        """Generate all output formats"""
        log(f"Generating outputs to: {output_dir}", LogLevel.INFO)
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize output generators
        outputs = {
            'cs': CSDumpGenerator(),
            'json': JSONExporter(),
            'ida_python': IDAScriptGenerator(),
            'cheat_engine': None  # Will be implemented
        }
        
        for format_name in self.config['output']['formats']:
            if format_name in outputs and outputs[format_name]:
                try:
                    output_path = os.path.join(output_dir, f"dump.{format_name}")
                    outputs[format_name].generate(
                        parser=self.parser,
                        analyzer=self.analyzer,
                        output_path=output_path,
                        config=self.config['output']
                    )
                    log(f"✓ Generated {format_name} output", LogLevel.SUCCESS)
                except Exception as e:
                    log(f"✗ Failed to generate {format_name}: {e}", LogLevel.ERROR)
        
        # Generate SDK if enabled
        if self.config['output']['generate_sdk']:
            self.generate_sdk(output_dir)
    
    def generate_sdk(self, output_dir: str):
        """Generate complete SDK for modding"""
        log("Generating SDK...", LogLevel.INFO)
        
        sdk_dir = os.path.join(output_dir, "sdk")
        os.makedirs(sdk_dir, exist_ok=True)
        
        # Generate C# SDK
        cs_sdk_dir = os.path.join(sdk_dir, "csharp")
        os.makedirs(cs_sdk_dir, exist_ok=True)
        
        # Copy template files
        templates = ["ModMenu.cs", "Hooks.cs", "MemoryUtils.cs"]
        for template in templates:
            template_path = os.path.join("templates", template)
            if os.path.exists(template_path):
                with open(template_path, 'r') as f:
                    content = f.read()
                
                # Replace placeholders
                content = content.replace("{{GAME_NAME}}", "TargetGame")
                content = content.replace("{{OFFSETS}}", str(len(self.parser.metadata.methods)))
                
                output_path = os.path.join(cs_sdk_dir, template)
                with open(output_path, 'w') as f:
                    f.write(content)
        
        log(f"✓ SDK generated at: {sdk_dir}", LogLevel.SUCCESS)
    
    def setup_hooking(self):
        """Initialize runtime hooking if enabled"""
        if self.config['hooking']['enable']:
            log("Initializing hooking system...", LogLevel.INFO)
            self.hook_manager = HookManager()
            
            # Load hook modules
            self.hook_manager.load_hooks_from_dir("hooks")
            
            target_process = self.config['hooking']['target_process']
            if target_process:
                log(f"Target process: {target_process}", LogLevel.INFO)
                # In real implementation, this would attach to process
    
    def run(self, il2cpp_path: str, metadata_path: str, output_dir: str):
        """Main execution flow"""
        try:
            # 1. Load plugins
            self.load_plugins()
            
            # 2. Initialize parser
            if not self.initialize_parser(il2cpp_path, metadata_path):
                return False
            
            # 3. Run analysis with plugins
            self.run_analysis()
            
            # 4. Generate outputs
            self.generate_outputs(output_dir)
            
            # 5. Setup hooking if enabled
            self.setup_hooking()
            
            log("=" * 60, LogLevel.INFO)
            log("DUMP COMPLETED SUCCESSFULLY!", LogLevel.SUCCESS)
            log(f"Output directory: {output_dir}", LogLevel.INFO)
            
            # Show statistics
            if self.analyzer:
                stats = self.analyzer.get_statistics()
                log(f"Types analyzed: {stats['types']}", LogLevel.INFO)
                log(f"Methods found: {stats['methods']}", LogLevel.INFO)
                log(f"Strings extracted: {stats['strings']}", LogLevel.INFO)
                log(f"Patterns detected: {stats['patterns']}", LogLevel.INFO)
            
            return True
            
        except Exception as e:
            log(f"Fatal error: {e}", LogLevel.CRITICAL)
            import traceback
            traceback.print_exc()
            return False

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Il2Cpp Dumper Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s game.so metadata.dat -o ./dump
  %(prog)s game.so metadata.dat --plugins all --hook-process "game.exe"
  %(prog)s --config custom_config.yaml game.so metadata.dat
        '''
    )
    
    parser.add_argument('il2cpp', help='Path to libil2cpp.so or GameAssembly.dll')
    parser.add_argument('metadata', help='Path to global-metadata.dat')
    parser.add_argument('-o', '--output', default='./il2cpp_dump', 
                       help='Output directory (default: ./il2cpp_dump)')
    parser.add_argument('-c', '--config', default='config.yaml',
                       help='Configuration file (default: config.yaml)')
    parser.add_argument('-p', '--plugins', nargs='+', 
                       help='Specific plugins to load (default: all enabled)')
    parser.add_argument('--hook', action='store_true',
                       help='Enable runtime hooking')
    parser.add_argument('--hook-process', help='Target process name for hooking')
    parser.add_argument('--deep-scan', action='store_true',
                       help='Enable deep scanning (slower but more thorough)')
    parser.add_argument('--verbose', '-v', action='count', default=0,
                       help='Increase verbosity level')
    
    args = parser.parse_args()
    
    # Update config based on args
    dumper = AdvancedIl2CppDumper(args.config)
    
    if args.plugins:
        dumper.config['plugins']['enabled'] = args.plugins
    
    if args.hook or args.hook_process:
        dumper.config['hooking']['enable'] = True
        if args.hook_process:
            dumper.config['hooking']['target_process'] = args.hook_process
    
    if args.deep_scan:
        dumper.config['analysis']['deep_scan'] = True
    
    # Set log level based on verbosity
    if args.verbose >= 2:
        dumper.config['logging']['level'] = 'DEBUG'
    elif args.verbose >= 1:
        dumper.config['logging']['level'] = 'INFO'
    
    # Run dumper
    success = dumper.run(args.il2cpp, args.metadata, args.output)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
