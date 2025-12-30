from __future__ import annotations

import time
import threading
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from ..utils.logging_config import get_logger

logger = get_logger("scheduler")

class ScheduleFrequency(Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

@dataclass
class ScheduledScan:
    id: str
    url: str
    standards: List[str]
    mode: str
    frequency: ScheduleFrequency
    next_run: datetime
    enabled: bool = True
    last_run: Optional[datetime] = None
    last_status: Optional[str] = None
    callback: Optional[Callable] = None
    max_pages: Optional[int] = None
    max_depth: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class ScanScheduler:
    def __init__(self):
        self.scheduled_scans: Dict[str, ScheduledScan] = {}
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
    
    def add_schedule(
        self,
        schedule_id: str,
        url: str,
        standards: List[str],
        mode: str,
        frequency: ScheduleFrequency,
        start_time: Optional[datetime] = None,
        callback: Optional[Callable] = None,
        **kwargs
    ) -> ScheduledScan:
        if start_time is None:
            start_time = datetime.now()
        
        scheduled_scan = ScheduledScan(
            id=schedule_id,
            url=url,
            standards=standards,
            mode=mode,
            frequency=frequency,
            next_run=start_time,
            callback=callback,
            max_pages=kwargs.get('max_pages'),
            max_depth=kwargs.get('max_depth'),
            metadata=kwargs.get('metadata', {}),
        )
        
        with self.lock:
            self.scheduled_scans[schedule_id] = scheduled_scan
        
        logger.info(f"Added scheduled scan: {schedule_id} for {url} ({frequency.value})")
        return scheduled_scan
    
    def remove_schedule(self, schedule_id: str) -> bool:
        with self.lock:
            if schedule_id in self.scheduled_scans:
                del self.scheduled_scans[schedule_id]
                logger.info(f"Removed scheduled scan: {schedule_id}")
                return True
        return False
    
    def enable_schedule(self, schedule_id: str) -> bool:
        with self.lock:
            if schedule_id in self.scheduled_scans:
                self.scheduled_scans[schedule_id].enabled = True
                logger.info(f"Enabled scheduled scan: {schedule_id}")
                return True
        return False
    
    def disable_schedule(self, schedule_id: str) -> bool:
        with self.lock:
            if schedule_id in self.scheduled_scans:
                self.scheduled_scans[schedule_id].enabled = False
                logger.info(f"Disabled scheduled scan: {schedule_id}")
                return True
        return False
    
    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        with self.lock:
            return self.scheduled_scans.get(schedule_id)
    
    def list_schedules(self) -> List[ScheduledScan]:
        with self.lock:
            return list(self.scheduled_scans.values())
    
    def start(self) -> None:
        if self.running:
            logger.warning("Scheduler is already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("Scheduler started")
    
    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Scheduler stopped")
    
    def _run_loop(self) -> None:
        while self.running:
            try:
                self._check_and_run_scans()
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}", exc_info=True)
            
            time.sleep(60)
    
    def _check_and_run_scans(self) -> None:
        now = datetime.now()
        
        with self.lock:
            scans_to_run = [
                scan for scan in self.scheduled_scans.values()
                if scan.enabled and scan.next_run <= now
            ]
        
        for scan in scans_to_run:
            try:
                self._execute_scheduled_scan(scan)
            except Exception as e:
                logger.error(f"Failed to execute scheduled scan {scan.id}: {e}", exc_info=True)
                scan.last_status = "failed"
    
    def _execute_scheduled_scan(self, scan: ScheduledScan) -> None:
        logger.info(f"Executing scheduled scan: {scan.id}")
        
        scan.last_run = datetime.now()
        
        try:
            if scan.callback:
                scan.callback(scan)
            
            scan.last_status = "completed"
            logger.info(f"Scheduled scan completed: {scan.id}")
        except Exception as e:
            scan.last_status = "failed"
            logger.error(f"Scheduled scan failed: {scan.id} - {e}")
            raise
        finally:
            scan.next_run = self._calculate_next_run(scan)
    
    def _calculate_next_run(self, scan: ScheduledScan) -> datetime:
        now = datetime.now()
        
        if scan.frequency == ScheduleFrequency.HOURLY:
            return now + timedelta(hours=1)
        elif scan.frequency == ScheduleFrequency.DAILY:
            return now + timedelta(days=1)
        elif scan.frequency == ScheduleFrequency.WEEKLY:
            return now + timedelta(weeks=1)
        elif scan.frequency == ScheduleFrequency.MONTHLY:
            return now + timedelta(days=30)
        else:
            return now + timedelta(days=1)

_global_scheduler: Optional[ScanScheduler] = None

def get_scheduler() -> ScanScheduler:
    global _global_scheduler
    if _global_scheduler is None:
        _global_scheduler = ScanScheduler()
    return _global_scheduler
