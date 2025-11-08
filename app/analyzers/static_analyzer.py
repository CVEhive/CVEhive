"""
Static Code Analysis Module
Performs baseline static analysis on exploit code before dynamic testing
"""

import logging
import ast
import subprocess
import tempfile
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import json

logger = logging.getLogger(__name__)


class StaticAnalyzer:
    """
    Performs static analysis on code to determine:
    - Syntax validity
    - Code structure
    - Security patterns
    - Dependencies
    - Execution requirements
    """
    
    def __init__(self):
        self.tools_available = self._check_tools()
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check which static analysis tools are available."""
        tools = {
            'semgrep': False,
            'bandit': False,
            'pylint': False,
            'ast': True  # Always available
        }
        
        # Check Semgrep
        try:
            result = subprocess.run(['semgrep', '--version'], 
                                  capture_output=True, timeout=5)
            tools['semgrep'] = result.returncode == 0
        except:
            pass
        
        # Check Bandit
        try:
            result = subprocess.run(['bandit', '--version'], 
                                  capture_output=True, timeout=5)
            tools['bandit'] = result.returncode == 0
        except:
            pass
        
        # Check Pylint
        try:
            result = subprocess.run(['pylint', '--version'], 
                                  capture_output=True, timeout=5)
            tools['pylint'] = result.returncode == 0
        except:
            pass
        
        return tools
    
    def analyze_code(self, code: str, language: str, file_path: Optional[str] = None) -> Dict:
        """
        Perform comprehensive static analysis on code.
        
        Args:
            code: Source code to analyze
            language: Programming language (python, c, javascript, etc.)
            file_path: Optional file path for context
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting static analysis for {language} code")
        
        results = {
            'language': language,
            'file_path': file_path,
            'timestamp': None,
            'syntax_valid': False,
            'analysis_tools': {},
            'code_metrics': {},
            'security_analysis': {},
            'dependencies': [],
            'execution_requirements': {},
            'readme_instructions': None,
            'baseline_score': 0
        }
        
        try:
            # Basic syntax validation
            syntax_result = self._validate_syntax(code, language)
            results['syntax_valid'] = syntax_result['valid']
            results['syntax_errors'] = syntax_result.get('errors', [])
            
            # Language-specific analysis
            if language.lower() == 'python':
                results['analysis_tools'].update(self._analyze_python(code))
            elif language.lower() in ['c', 'cpp']:
                results['analysis_tools'].update(self._analyze_c_cpp(code, language))
            elif language.lower() == 'javascript':
                results['analysis_tools'].update(self._analyze_javascript(code))
            
            # Code metrics
            results['code_metrics'] = self._calculate_metrics(code, language)
            
            # Security analysis
            results['security_analysis'] = self._analyze_security(code, language)
            
            # Extract dependencies
            results['dependencies'] = self._extract_dependencies(code, language)
            
            # Execution requirements
            results['execution_requirements'] = self._determine_execution_requirements(
                code, language, results['dependencies']
            )
            
            # Calculate baseline score
            results['baseline_score'] = self._calculate_baseline_score(results)
            
            results['timestamp'] = datetime.utcnow().isoformat()
            
        except Exception as e:
            logger.error(f"Error in static analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _validate_syntax(self, code: str, language: str) -> Dict:
        """Validate code syntax."""
        result = {'valid': False, 'errors': []}
        
        try:
            if language.lower() == 'python':
                compile(code, '<string>', 'exec')
                result['valid'] = True
            elif language.lower() in ['c', 'cpp']:
                # Basic C/C++ syntax check
                if '{' in code and '}' in code:
                    result['valid'] = True
                else:
                    result['errors'].append('Missing braces')
            elif language.lower() == 'javascript':
                # Basic JS check
                if code.count('{') == code.count('}'):
                    result['valid'] = True
                else:
                    result['errors'].append('Mismatched braces')
            else:
                result['valid'] = True  # Assume valid for unknown languages
                
        except SyntaxError as e:
            result['errors'].append(f"Syntax error: {str(e)}")
        except Exception as e:
            result['errors'].append(f"Validation error: {str(e)}")
        
        return result
    
    def _analyze_python(self, code: str) -> Dict:
        """Analyze Python code with available tools."""
        analysis = {}
        
        # AST Analysis (always available)
        try:
            tree = ast.parse(code)
            analysis['ast'] = {
                'valid': True,
                'functions': len([n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]),
                'classes': len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]),
                'imports': [self._extract_import_name(n) for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))],
                'dangerous_calls': self._find_dangerous_calls_ast(tree)
            }
        except SyntaxError as e:
            analysis['ast'] = {'valid': False, 'error': str(e)}
        
        # Bandit (if available)
        if self.tools_available['bandit']:
            analysis['bandit'] = self._run_bandit(code)
        
        # Semgrep (if available)
        if self.tools_available['semgrep']:
            analysis['semgrep'] = self._run_semgrep(code, 'python')
        
        return analysis
    
    def _analyze_c_cpp(self, code: str, language: str) -> Dict:
        """Analyze C/C++ code."""
        analysis = {}
        
        # Basic pattern analysis
        dangerous_patterns = {
            'strcpy': code.count('strcpy'),
            'strcat': code.count('strcat'),
            'sprintf': code.count('sprintf'),
            'gets': code.count('gets'),
            'system': code.count('system('),
        }
        
        analysis['patterns'] = {
            'dangerous_functions': {k: v for k, v in dangerous_patterns.items() if v > 0},
            'has_main': 'main' in code or 'int main' in code,
            'includes': [line.strip() for line in code.split('\n') if line.strip().startswith('#include')]
        }
        
        # Semgrep for C/C++
        if self.tools_available['semgrep']:
            analysis['semgrep'] = self._run_semgrep(code, language)
        
        return analysis
    
    def _analyze_javascript(self, code: str) -> Dict:
        """Analyze JavaScript code."""
        analysis = {}
        
        dangerous_patterns = {
            'eval': code.count('eval('),
            'Function': code.count('Function('),
            'innerHTML': code.count('innerHTML'),
            'document.write': code.count('document.write'),
        }
        
        analysis['patterns'] = {
            'dangerous_functions': {k: v for k, v in dangerous_patterns.items() if v > 0},
            'has_require': 'require(' in code,
            'has_import': 'import ' in code or 'import(' in code
        }
        
        return analysis
    
    def _run_bandit(self, code: str) -> Dict:
        """Run Bandit security scanner on Python code."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code)
                f.flush()
                
                result = subprocess.run(
                    ['bandit', '-f', 'json', '-q', f.name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                os.unlink(f.name)
                
                if result.returncode == 0:
                    return {'success': True, 'output': json.loads(result.stdout)}
                else:
                    return {'success': False, 'error': result.stderr}
                    
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _run_semgrep(self, code: str, language: str) -> Dict:
        """Run Semgrep on code."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{language}', delete=False) as f:
                f.write(code)
                f.flush()
                
                result = subprocess.run(
                    ['semgrep', '--config=auto', '--json', f.name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                os.unlink(f.name)
                
                if result.returncode == 0:
                    return {'success': True, 'output': json.loads(result.stdout)}
                else:
                    return {'success': False, 'error': result.stderr}
                    
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _extract_import_name(self, node) -> str:
        """Extract import name from AST node."""
        if isinstance(node, ast.Import):
            return node.names[0].name if node.names else ''
        elif isinstance(node, ast.ImportFrom):
            return node.module or ''
        return ''
    
    def _find_dangerous_calls_ast(self, tree) -> List[str]:
        """Find dangerous function calls in AST."""
        dangerous = []
        dangerous_funcs = ['eval', 'exec', 'compile', '__import__', 'system', 'popen']
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in dangerous_funcs:
                        dangerous.append(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in dangerous_funcs:
                        dangerous.append(node.func.attr)
        
        return dangerous
    
    def _calculate_metrics(self, code: str, language: str) -> Dict:
        """Calculate code metrics."""
        lines = code.split('\n')
        return {
            'total_lines': len(lines),
            'code_lines': len([l for l in lines if l.strip() and not l.strip().startswith('#')]),
            'comment_lines': len([l for l in lines if l.strip().startswith('#')]),
            'blank_lines': len([l for l in lines if not l.strip()]),
            'complexity': self._estimate_complexity(code)
        }
    
    def _estimate_complexity(self, code: str) -> int:
        """Estimate code complexity."""
        complexity = 1  # Base complexity
        
        # Count control structures
        control_keywords = ['if', 'for', 'while', 'switch', 'case', 'try', 'except', 'catch']
        for keyword in control_keywords:
            complexity += code.count(f' {keyword} ') + code.count(f' {keyword}(')
        
        return complexity
    
    def _analyze_security(self, code: str, language: str) -> Dict:
        """Analyze security patterns in code."""
        security = {
            'risk_level': 'low',
            'concerns': [],
            'dangerous_patterns': []
        }
        
        code_lower = code.lower()
        
        # High-risk patterns
        high_risk = ['system(', 'exec(', 'eval(', 'shell_exec', 'passthru', 'rm -rf']
        if any(pattern in code_lower for pattern in high_risk):
            security['risk_level'] = 'high'
            security['concerns'].append('Contains high-risk system commands')
        
        # Medium-risk patterns
        medium_risk = ['subprocess', 'os.system', 'popen', 'socket']
        if any(pattern in code_lower for pattern in medium_risk):
            if security['risk_level'] == 'low':
                security['risk_level'] = 'medium'
            security['concerns'].append('Contains system interaction')
        
        return security
    
    def _extract_dependencies(self, code: str, language: str) -> List[str]:
        """Extract dependencies from code."""
        dependencies = []
        
        if language.lower() == 'python':
            # Extract imports
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            dependencies.append(alias.name.split('.')[0])
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            dependencies.append(node.module.split('.')[0])
            except:
                pass
        
        elif language.lower() == 'javascript':
            # Extract require/import
            import re
            requires = re.findall(r"require\(['\"]([^'\"]+)['\"]\)", code)
            imports = re.findall(r"import\s+.*\s+from\s+['\"]([^'\"]+)['\"]", code)
            dependencies.extend(requires + imports)
        
        return list(set(dependencies))  # Remove duplicates
    
    def _determine_execution_requirements(self, code: str, language: str, 
                                          dependencies: List[str]) -> Dict:
        """Determine what's needed to run the code."""
        requirements = {
            'language': language,
            'language_version': None,
            'dependencies': dependencies,
            'system_requirements': [],
            'environment_variables': [],
            'file_permissions': [],
            'network_access': False
        }
        
        code_lower = code.lower()
        
        # Check for network access
        if any(keyword in code_lower for keyword in ['socket', 'http', 'requests', 'urllib', 'curl']):
            requirements['network_access'] = True
        
        # Check for file operations
        if any(keyword in code_lower for keyword in ['open(', 'fopen', 'file_get_contents', 'readfile']):
            requirements['file_permissions'].append('read')
        if any(keyword in code_lower for keyword in ['write', 'fwrite', 'file_put_contents']):
            requirements['file_permissions'].append('write')
        
        # Check for environment variables
        import re
        env_vars = re.findall(r'os\.environ\[[\'\"]([^\'\"]+)[\'\"]\]', code)
        env_vars.extend(re.findall(r'process\.env\.(\w+)', code))
        requirements['environment_variables'] = list(set(env_vars))
        
        return requirements
    
    def _calculate_baseline_score(self, results: Dict) -> int:
        """
        Calculate baseline score (0-100) indicating code quality and readiness.
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            Score 0-100
        """
        score = 0
        
        # Syntax validity (30 points)
        if results.get('syntax_valid'):
            score += 30
        
        # Code metrics (20 points)
        metrics = results.get('code_metrics', {})
        if metrics.get('code_lines', 0) > 0:
            score += 10
        if metrics.get('complexity', 0) > 0:
            score += 10
        
        # Security analysis (25 points)
        security = results.get('security_analysis', {})
        risk_level = security.get('risk_level', 'high')
        if risk_level == 'low':
            score += 25
        elif risk_level == 'medium':
            score += 15
        else:
            score += 5  # High risk still gets some points
        
        # Dependencies identified (15 points)
        deps = results.get('dependencies', [])
        if deps:
            score += min(15, len(deps) * 3)
        
        # Execution requirements identified (10 points)
        exec_req = results.get('execution_requirements', {})
        if exec_req:
            score += 10
        
        return min(100, score)

