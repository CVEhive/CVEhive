import docker
import logging
import time
import tempfile
import os
import shutil
from typing import Dict, Optional, List, Tuple
from datetime import datetime, timedelta
import json
import subprocess

class DockerSandbox:
    """Docker-based sandbox for safely executing exploit code."""
    
    def __init__(self):
        try:
            self.client = docker.from_env()
            # Test Docker connection
            self.client.ping()
            logging.info("Docker client initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize Docker client: {str(e)}")
            self.client = None
    
    def is_available(self) -> bool:
        """Check if Docker is available and working."""
        return self.client is not None
    
    def create_sandbox_image(self, base_image: str = "ubuntu:20.04") -> bool:
        """
        Create a custom sandbox image with security tools and monitoring.
        
        Args:
            base_image (str): Base Docker image to use
            
        Returns:
            bool: True if image created successfully
        """
        if not self.client:
            return False
        
        dockerfile_content = f"""
FROM {base_image}

# Install basic tools and dependencies
RUN apt-get update && apt-get install -y \\
    python3 \\
    python3-pip \\
    gcc \\
    g++ \\
    make \\
    perl \\
    ruby \\
    nodejs \\
    npm \\
    php \\
    curl \\
    wget \\
    netcat \\
    nmap \\
    strace \\
    ltrace \\
    gdb \\
    vim \\
    nano \\
    && rm -rf /var/lib/apt/lists/*

# Install Python packages commonly used in exploits
RUN pip3 install requests pwntools scapy

# Create non-root user for running exploits
RUN useradd -m -s /bin/bash exploit_user

# Set up working directory
WORKDIR /exploit
RUN chown exploit_user:exploit_user /exploit

# Copy monitoring script
COPY monitor.sh /usr/local/bin/monitor.sh
RUN chmod +x /usr/local/bin/monitor.sh

# Switch to non-root user
USER exploit_user

# Set default command
CMD ["/bin/bash"]
"""
        
        monitor_script = """#!/bin/bash
# Monitor script for exploit execution
echo "Starting exploit monitoring..."
echo "PID: $$"
echo "User: $(whoami)"
echo "Working directory: $(pwd)"
echo "Environment variables:"
env | grep -E "(PATH|HOME|USER)" | head -10
echo "Network interfaces:"
ip addr show | grep -E "(inet|link)" | head -10
echo "Processes:"
ps aux | head -10
echo "Disk usage:"
df -h | head -5
echo "Memory usage:"
free -h
echo "Starting exploit execution..."
exec "$@"
"""
        
        try:
            # Create temporary directory for build context
            with tempfile.TemporaryDirectory() as temp_dir:
                # Write Dockerfile
                dockerfile_path = os.path.join(temp_dir, 'Dockerfile')
                with open(dockerfile_path, 'w') as f:
                    f.write(dockerfile_content)
                
                # Write monitor script
                monitor_path = os.path.join(temp_dir, 'monitor.sh')
                with open(monitor_path, 'w') as f:
                    f.write(monitor_script)
                
                # Build image
                logging.info("Building CVEhive sandbox image...")
                image, build_logs = self.client.images.build(
                    path=temp_dir,
                    tag="cvehive-sandbox:latest",
                    rm=True,
                    forcerm=True
                )
                
                logging.info("Sandbox image built successfully")
                return True
                
        except Exception as e:
            logging.error(f"Failed to build sandbox image: {str(e)}")
            return False
    
    def execute_exploit(self, 
                       exploit_code: str, 
                       language: str = "python",
                       timeout: int = 30,
                       network_enabled: bool = False) -> Dict:
        """
        Execute exploit code in a sandboxed environment.
        
        Args:
            exploit_code (str): The exploit code to execute
            language (str): Programming language of the exploit
            timeout (int): Execution timeout in seconds
            network_enabled (bool): Whether to enable network access
            
        Returns:
            Dict: Execution results including output, errors, and metrics
        """
        if not self.client:
            return {
                'success': False,
                'error': 'Docker not available',
                'output': '',
                'stderr': '',
                'execution_time': 0,
                'exit_code': -1
            }
        
        # Ensure sandbox image exists
        try:
            self.client.images.get("cvehive-sandbox:latest")
        except docker.errors.ImageNotFound:
            if not self.create_sandbox_image():
                return {
                    'success': False,
                    'error': 'Failed to create sandbox image',
                    'output': '',
                    'stderr': '',
                    'execution_time': 0,
                    'exit_code': -1
                }
        
        # Prepare exploit file
        file_extension = self._get_file_extension(language)
        exploit_filename = f"exploit{file_extension}"
        
        # Create temporary directory for exploit files
        with tempfile.TemporaryDirectory() as temp_dir:
            exploit_path = os.path.join(temp_dir, exploit_filename)
            
            # Write exploit code to file
            with open(exploit_path, 'w') as f:
                f.write(exploit_code)
            
            # Prepare execution command
            exec_command = self._get_execution_command(language, exploit_filename)
            
            # Configure container settings
            container_config = {
                'image': 'cvehive-sandbox:latest',
                'command': ['bash', '-c', f'cd /exploit && {exec_command}'],
                'working_dir': '/exploit',
                'user': 'exploit_user',
                'mem_limit': '512m',  # Limit memory usage
                'cpu_quota': 50000,   # Limit CPU usage (50% of one core)
                'cpu_period': 100000,
                'volumes': {temp_dir: {'bind': '/exploit', 'mode': 'ro'}},
                'network_disabled': not network_enabled,
                'remove': True,  # Auto-remove container after execution
                'stdout': True,
                'stderr': True,
                'detach': False
            }
            
            # Add security options
            if not network_enabled:
                container_config['network_mode'] = 'none'
            
            start_time = time.time()
            
            try:
                # Run container
                logging.info(f"Executing {language} exploit in sandbox...")
                
                container = self.client.containers.run(**container_config)
                
                execution_time = time.time() - start_time
                
                # Get output
                output = container.decode('utf-8') if isinstance(container, bytes) else str(container)
                
                return {
                    'success': True,
                    'error': None,
                    'output': output,
                    'stderr': '',
                    'execution_time': execution_time,
                    'exit_code': 0,
                    'language': language,
                    'network_enabled': network_enabled,
                    'timeout_used': timeout
                }
                
            except docker.errors.ContainerError as e:
                execution_time = time.time() - start_time
                return {
                    'success': False,
                    'error': f'Container execution failed: {str(e)}',
                    'output': e.container.logs().decode('utf-8') if e.container else '',
                    'stderr': str(e),
                    'execution_time': execution_time,
                    'exit_code': e.exit_status,
                    'language': language,
                    'network_enabled': network_enabled,
                    'timeout_used': timeout
                }
                
            except Exception as e:
                execution_time = time.time() - start_time
                return {
                    'success': False,
                    'error': f'Unexpected error: {str(e)}',
                    'output': '',
                    'stderr': str(e),
                    'execution_time': execution_time,
                    'exit_code': -1,
                    'language': language,
                    'network_enabled': network_enabled,
                    'timeout_used': timeout
                }
    
    def execute_with_target(self, 
                           exploit_code: str, 
                           target_config: Dict,
                           language: str = "python",
                           timeout: int = 60) -> Dict:
        """
        Execute exploit against a specific target in a controlled environment.
        
        Args:
            exploit_code (str): The exploit code to execute
            target_config (Dict): Target configuration (vulnerable service setup)
            language (str): Programming language of the exploit
            timeout (int): Execution timeout in seconds
            
        Returns:
            Dict: Execution results including success indicators
        """
        if not self.client:
            return {'success': False, 'error': 'Docker not available'}
        
        # Create a network for the test
        network_name = f"cvehive-test-{int(time.time())}"
        
        try:
            # Create custom network
            network = self.client.networks.create(
                network_name,
                driver="bridge",
                internal=True  # No external access
            )
            
            # Start target container
            target_container = self._start_target_container(target_config, network_name)
            if not target_container:
                return {'success': False, 'error': 'Failed to start target container'}
            
            # Wait for target to be ready
            time.sleep(5)
            
            # Execute exploit against target
            exploit_result = self._execute_exploit_against_target(
                exploit_code, language, target_container, network_name, timeout
            )
            
            # Analyze results
            analysis = self._analyze_exploit_results(exploit_result, target_container)
            
            return {
                'success': exploit_result.get('success', False),
                'exploit_output': exploit_result.get('output', ''),
                'target_logs': self._get_container_logs(target_container),
                'analysis': analysis,
                'execution_time': exploit_result.get('execution_time', 0),
                'network_traffic': self._capture_network_traffic(network_name),
                'target_config': target_config
            }
            
        except Exception as e:
            logging.error(f"Error in target-based execution: {str(e)}")
            return {'success': False, 'error': str(e)}
            
        finally:
            # Cleanup
            try:
                # Stop and remove containers
                for container in self.client.containers.list(all=True):
                    if network_name in [net.name for net in container.attrs.get('NetworkSettings', {}).get('Networks', {})]:
                        container.stop(timeout=5)
                        container.remove()
                
                # Remove network
                network.remove()
                
            except Exception as e:
                logging.warning(f"Cleanup error: {str(e)}")
    
    def _get_file_extension(self, language: str) -> str:
        """Get file extension for programming language."""
        extensions = {
            'python': '.py',
            'c': '.c',
            'cpp': '.cpp',
            'perl': '.pl',
            'ruby': '.rb',
            'shell': '.sh',
            'bash': '.sh',
            'php': '.php',
            'javascript': '.js',
            'java': '.java'
        }
        return extensions.get(language.lower(), '.txt')
    
    def _get_execution_command(self, language: str, filename: str) -> str:
        """Get execution command for programming language."""
        commands = {
            'python': f'python3 {filename}',
            'c': f'gcc {filename} -o exploit && ./exploit',
            'cpp': f'g++ {filename} -o exploit && ./exploit',
            'perl': f'perl {filename}',
            'ruby': f'ruby {filename}',
            'shell': f'bash {filename}',
            'bash': f'bash {filename}',
            'php': f'php {filename}',
            'javascript': f'node {filename}',
            'java': f'javac {filename} && java $(basename {filename} .java)'
        }
        return commands.get(language.lower(), f'cat {filename}')
    
    def _start_target_container(self, target_config: Dict, network_name: str) -> Optional[object]:
        """Start a target container based on configuration."""
        try:
            container_config = {
                'image': target_config.get('image', 'ubuntu:20.04'),
                'command': target_config.get('command', ['sleep', '300']),
                'network': network_name,
                'detach': True,
                'remove': True
            }
            
            # Add port mappings if specified
            if 'ports' in target_config:
                container_config['ports'] = target_config['ports']
            
            # Add environment variables
            if 'environment' in target_config:
                container_config['environment'] = target_config['environment']
            
            container = self.client.containers.run(**container_config)
            logging.info(f"Started target container: {container.id[:12]}")
            return container
            
        except Exception as e:
            logging.error(f"Failed to start target container: {str(e)}")
            return None
    
    def _execute_exploit_against_target(self, 
                                      exploit_code: str, 
                                      language: str, 
                                      target_container: object,
                                      network_name: str,
                                      timeout: int) -> Dict:
        """Execute exploit against target container."""
        # Modify exploit code to target the container
        target_ip = self._get_container_ip(target_container, network_name)
        
        # Simple IP replacement (this could be more sophisticated)
        modified_code = exploit_code.replace('localhost', target_ip)
        modified_code = modified_code.replace('127.0.0.1', target_ip)
        
        # Execute exploit with network access
        return self.execute_exploit(
            modified_code, 
            language, 
            timeout, 
            network_enabled=True
        )
    
    def _get_container_ip(self, container: object, network_name: str) -> str:
        """Get container IP address in specific network."""
        try:
            container.reload()
            networks = container.attrs['NetworkSettings']['Networks']
            if network_name in networks:
                return networks[network_name]['IPAddress']
        except Exception as e:
            logging.warning(f"Failed to get container IP: {str(e)}")
        
        return '172.17.0.2'  # Default fallback
    
    def _get_container_logs(self, container: object) -> str:
        """Get logs from container."""
        try:
            return container.logs().decode('utf-8')
        except Exception as e:
            logging.warning(f"Failed to get container logs: {str(e)}")
            return ''
    
    def _analyze_exploit_results(self, exploit_result: Dict, target_container: object) -> Dict:
        """Analyze exploit execution results."""
        analysis = {
            'exploit_executed': exploit_result.get('success', False),
            'target_affected': False,
            'indicators': [],
            'severity': 'low'
        }
        
        # Check exploit output for success indicators
        output = exploit_result.get('output', '').lower()
        success_indicators = [
            'exploit successful', 'shell spawned', 'connection established',
            'payload executed', 'vulnerability confirmed', 'access granted'
        ]
        
        for indicator in success_indicators:
            if indicator in output:
                analysis['indicators'].append(f"Found success indicator: {indicator}")
                analysis['target_affected'] = True
        
        # Check target logs for compromise indicators
        target_logs = self._get_container_logs(target_container).lower()
        compromise_indicators = [
            'segmentation fault', 'buffer overflow', 'access violation',
            'unauthorized access', 'privilege escalation', 'shell access'
        ]
        
        for indicator in compromise_indicators:
            if indicator in target_logs:
                analysis['indicators'].append(f"Target compromise indicator: {indicator}")
                analysis['target_affected'] = True
        
        # Determine severity
        if analysis['target_affected']:
            if any('shell' in ind or 'escalation' in ind for ind in analysis['indicators']):
                analysis['severity'] = 'high'
            else:
                analysis['severity'] = 'medium'
        
        return analysis
    
    def _capture_network_traffic(self, network_name: str) -> Dict:
        """Capture and analyze network traffic (simplified)."""
        # This is a placeholder for network traffic analysis
        # In a real implementation, you might use tcpdump or similar tools
        return {
            'packets_captured': 0,
            'protocols_seen': [],
            'suspicious_activity': False
        }
    
    def cleanup_old_containers(self, max_age_hours: int = 1):
        """Clean up old containers and images."""
        if not self.client:
            return
        
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
            
            # Remove old containers
            for container in self.client.containers.list(all=True):
                created = datetime.fromisoformat(
                    container.attrs['Created'].replace('Z', '+00:00')
                )
                if created < cutoff_time and 'cvehive' in container.name:
                    try:
                        container.stop(timeout=5)
                        container.remove()
                        logging.info(f"Removed old container: {container.name}")
                    except Exception as e:
                        logging.warning(f"Failed to remove container {container.name}: {str(e)}")
            
            # Remove unused networks
            for network in self.client.networks.list():
                if 'cvehive-test-' in network.name:
                    try:
                        network.remove()
                        logging.info(f"Removed old network: {network.name}")
                    except Exception as e:
                        logging.warning(f"Failed to remove network {network.name}: {str(e)}")
                        
        except Exception as e:
            logging.error(f"Error during cleanup: {str(e)}")
    
    def get_system_info(self) -> Dict:
        """Get Docker system information."""
        if not self.client:
            return {'available': False}
        
        try:
            info = self.client.info()
            return {
                'available': True,
                'version': self.client.version(),
                'containers_running': info.get('ContainersRunning', 0),
                'containers_total': info.get('Containers', 0),
                'images_total': info.get('Images', 0),
                'memory_total': info.get('MemTotal', 0),
                'cpu_count': info.get('NCPU', 0)
            }
        except Exception as e:
            logging.error(f"Failed to get Docker info: {str(e)}")
            return {'available': False, 'error': str(e)} 