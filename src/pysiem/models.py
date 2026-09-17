from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class EventType(Enum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    SSH_LOGIN = "ssh_login"
    WEB_REQUEST = "web_request"
    APP_LOG = "app_log"
    SYSTEM_EVENT = "system_event"
    UNKNOWN = "unknown"


@dataclass
class RawEvent:
    timestamp: datetime
    source: str
    event_type: EventType
    username: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    port: int = 0
    status: str = ""
    message: str = ""
    severity: Severity = Severity.LOW
    raw_log: str = ""
    hostname: str = ""
    protocol: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type.value,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "port": self.port,
            "status": self.status,
            "message": self.message,
            "severity": self.severity.value,
            "raw_log": self.raw_log,
            "hostname": self.hostname,
            "protocol": self.protocol,
        }


@dataclass
class DetectionResult:
    rule_id: str
    rule_name: str
    description: str
    severity: Severity
    source_ip: str
    timestamp: datetime
    mitre_technique: str
    related_events: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "mitre_technique": self.mitre_technique,
            "related_events": self.related_events,
            "details": self.details,
        }


@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str = ""
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.LOW
    status: AlertStatus = AlertStatus.NEW
    source_ip: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    description: str = ""
    mitre_technique: str = ""
    related_events: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "status": self.status.value,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "related_events": self.related_events,
            "details": self.details,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class DetectionRule:
    id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    threshold: int = 5
    time_window: int = 300
    mitre_technique: str = ""
    rule_type: str = ""
    enabled: bool = True
    pattern: str = ""
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "threshold": self.threshold,
            "time_window": self.time_window,
            "mitre_technique": self.mitre_technique,
            "rule_type": self.rule_type,
            "enabled": self.enabled,
            "pattern": self.pattern,
            "fields": self.fields,
        }
