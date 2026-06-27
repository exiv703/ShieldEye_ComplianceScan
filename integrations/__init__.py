"""ShieldEye ComplianceScan integration clients.

Provides typed HTTP clients for importing scan results from external
ShieldEye services (Core and SurfaceScan) and correlating surface
findings to compliance controls.
"""

from integrations.core_client import CoreClient, CoreScanResult
from integrations.surfacescan_client import SurfaceFinding, SurfaceScanClient

__all__ = [
    "CoreClient",
    "CoreScanResult",
    "SurfaceFinding",
    "SurfaceScanClient",
]
