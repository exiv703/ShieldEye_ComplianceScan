import platform
import os
from typing import Literal, Optional

DistroType = Literal['fedora', 'rhel', 'arch', 'unknown']

def detect_distro() -> DistroType:

    if not platform.system().lower() == 'linux':
        return 'unknown'
    
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            content = f.read().lower()
            
            if 'fedora' in content:
                return 'fedora'
            elif any(distro in content for distro in ['rhel', 'red hat', 'centos', 'rocky', 'almalinux']):
                return 'rhel'
            elif 'arch' in content:
                return 'arch'
    
    if os.path.exists('/etc/fedora-release'):
        return 'fedora'
    elif os.path.exists('/etc/redhat-release'):
        return 'rhel'
    elif os.path.exists('/etc/arch-release'):
        return 'arch'
    
    return 'unknown'

def is_fedora_based() -> bool:

    distro = detect_distro()
    return distro in ('fedora', 'rhel')

def is_arch_based() -> bool:

    return detect_distro() == 'arch'

def get_distro_name() -> str:

    distro = detect_distro()
    return {
        'fedora': 'Fedora',
        'rhel': 'RHEL/CentOS',
        'arch': 'Arch Linux',
        'unknown': 'Unknown'
    }.get(distro, 'Unknown')
