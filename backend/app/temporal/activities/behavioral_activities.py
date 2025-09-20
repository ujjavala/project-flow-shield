"""
Temporal Activities for Behavioral Analytics and Fraud Detection
Provides durable, reliable behavioral analysis using Temporal's activity framework
"""

import logging
import asyncio
import json
import hashlib
import geoip2.database
import geoip2.errors
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
from user_agents import parse as parse_user_agent
from math import radians, cos, sin, asin, sqrt

from temporalio import activity
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, update, delete, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.database.connection import AsyncSessionLocal
from app.models.user import User

logger = logging.getLogger(__name__)

class BehavioralActivities:
    """Behavioral analytics activities for Temporal workflows"""

    def __init__(self):
        self.redis_client = None
        self.geoip_reader = None

    async def _get_redis(self):
        """Get Redis client for caching"""
        if self.redis_client is None:
            try:
                redis_host = "redis"  # Docker service name
                redis_port = 6379
                self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
                await self.redis_client.ping()
                logger.info("Behavioral Analytics Redis connected successfully")
            except Exception as e:
                logger.warning(f"Behavioral Analytics Redis connection failed: {e}")
                self.redis_client = None
        return self.redis_client

    def _get_geoip_reader(self):
        """Initialize GeoIP reader if available"""
        if self.geoip_reader is None:
            try:
                # Try to load GeoLite2 database (you would need to download this)
                self.geoip_reader = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb')
                logger.info("GeoIP database loaded successfully")
            except Exception as e:
                logger.warning(f"GeoIP database not available: {e}")
                self.geoip_reader = None
        return self.geoip_reader

    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two coordinates in kilometers"""
        # Haversine formula
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        r = 6371  # Radius of earth in kilometers
        return c * r

    def _create_device_fingerprint(self, user_agent: str, additional_data: Dict[str, Any] = None) -> str:
        """Create device fingerprint hash"""
        fingerprint_data = {
            "user_agent": user_agent,
            "additional": additional_data or {}
        }
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()

    @activity.defn(name="collect_user_behavior")
    async def collect_user_behavior(self, user_id: str, session_id: str, behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """Collect and store user behavior data"""
        activity.logger.info(f"Collecting behavior data for user {user_id}")

        try:
            async with AsyncSessionLocal() as session:
                # Store behavior data in database
                behavior_record = {
                    "user_id": user_id,
                    "session_id": session_id,
                    "event_type": behavior_data.get("event_type"),
                    "ip_address": behavior_data.get("ip_address"),
                    "user_agent": behavior_data.get("user_agent"),
                    "timestamp": behavior_data.get("timestamp"),
                    "geolocation": json.dumps(behavior_data.get("geolocation", {})),
                    "device_fingerprint": json.dumps(behavior_data.get("device_fingerprint", {})),
                    "additional_context": json.dumps(behavior_data.get("additional_context", {})),
                    "created_at": datetime.utcnow()
                }

                # Insert into behavior_analytics table
                await session.execute(
                    text("""
                        INSERT INTO behavior_analytics
                        (user_id, session_id, event_type, ip_address, user_agent, timestamp,
                         geolocation, device_fingerprint, additional_context, created_at)
                        VALUES (:user_id, :session_id, :event_type, :ip_address, :user_agent,
                                :timestamp, :geolocation, :device_fingerprint, :additional_context, :created_at)
                    """),
                    behavior_record
                )
                await session.commit()

                # Cache recent behavior for quick access
                redis_client = await self._get_redis()
                if redis_client:
                    cache_key = f"behavior:{user_id}:recent"
                    behavior_cache = json.dumps({
                        **behavior_data,
                        "collected_at": datetime.utcnow().isoformat()
                    })
                    await redis_client.lpush(cache_key, behavior_cache)
                    await redis_client.ltrim(cache_key, 0, 99)  # Keep last 100 events
                    await redis_client.expire(cache_key, 86400)  # 24 hours

                logger.info(f"Behavior data collected successfully for user {user_id}")

                return {
                    "success": True,
                    "user_id": user_id,
                    "session_id": session_id,
                    "behavior_data": behavior_data,
                    "timestamp": datetime.utcnow().isoformat()
                }

        except Exception as e:
            logger.error(f"Error collecting behavior data for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "user_id": user_id
            }

    @activity.defn(name="analyze_login_patterns")
    async def analyze_login_patterns(self, user_id: str, ip_address: str, user_agent: str, geolocation: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze login patterns for anomaly detection"""
        activity.logger.info(f"Analyzing login patterns for user {user_id}")

        try:
            async with AsyncSessionLocal() as session:
                # Get recent login history
                result = await session.execute(
                    text("""
                        SELECT ip_address, user_agent, geolocation, timestamp
                        FROM behavior_analytics
                        WHERE user_id = :user_id AND event_type = 'login'
                        AND created_at >= :since
                        ORDER BY created_at DESC
                        LIMIT 50
                    """),
                    {
                        "user_id": user_id,
                        "since": datetime.utcnow() - timedelta(days=30)
                    }
                )

                login_history = result.fetchall()

                anomalies = []
                risk_factors = []

                if login_history:
                    # Analyze IP patterns
                    ip_counts = Counter([row[0] for row in login_history])
                    if ip_address not in ip_counts:
                        anomalies.append("new_ip_address")
                        risk_factors.append({"type": "new_ip", "severity": "medium"})
                    elif ip_counts[ip_address] < 3:  # Rarely used IP
                        anomalies.append("rare_ip_address")
                        risk_factors.append({"type": "rare_ip", "severity": "low"})

                    # Analyze User Agent patterns
                    ua_counts = Counter([row[1] for row in login_history])
                    if user_agent not in ua_counts:
                        anomalies.append("new_user_agent")
                        risk_factors.append({"type": "new_device", "severity": "medium"})

                    # Analyze geolocation patterns
                    if geolocation and geolocation.get("latitude") and geolocation.get("longitude"):
                        current_lat = float(geolocation["latitude"])
                        current_lon = float(geolocation["longitude"])

                        for row in login_history[:10]:  # Check last 10 logins
                            try:
                                historical_geo = json.loads(row[2]) if row[2] else {}
                                if historical_geo.get("latitude") and historical_geo.get("longitude"):
                                    hist_lat = float(historical_geo["latitude"])
                                    hist_lon = float(historical_geo["longitude"])
                                    distance = self._calculate_distance(current_lat, current_lon, hist_lat, hist_lon)

                                    if distance > 1000:  # More than 1000km from usual locations
                                        anomalies.append("unusual_location")
                                        risk_factors.append({
                                            "type": "location_anomaly",
                                            "severity": "high",
                                            "distance_km": distance
                                        })
                                        break
                            except (json.JSONDecodeError, ValueError):
                                continue

                    # Analyze time patterns
                    login_hours = [datetime.fromisoformat(row[3]).hour for row in login_history if row[3]]
                    if login_hours:
                        current_hour = datetime.utcnow().hour
                        hour_counts = Counter(login_hours)
                        if current_hour not in hour_counts:
                            anomalies.append("unusual_time")
                            risk_factors.append({"type": "time_anomaly", "severity": "low"})

                else:
                    # First login - moderate risk
                    risk_factors.append({"type": "first_login", "severity": "medium"})

                logger.info(f"Login pattern analysis completed for user {user_id}")

                return {
                    "success": True,
                    "user_id": user_id,
                    "anomalies": anomalies,
                    "risk_factors": risk_factors,
                    "login_history_count": len(login_history),
                    "analysis_timestamp": datetime.utcnow().isoformat()
                }

        except Exception as e:
            logger.error(f"Error analyzing login patterns for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "user_id": user_id
            }

    @activity.defn(name="calculate_risk_score")
    async def calculate_risk_score(self, user_id: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk score using AI-powered analysis"""
        activity.logger.info(f"Calculating risk score for user {user_id}")

        try:
            base_score = 0.0
            risk_factors = []
            anomalies = []
            ai_analysis_result = None

            # Extract analysis components
            behavior_data = analysis_data.get("behavior_data", {})
            login_analysis = analysis_data.get("login_analysis", {})
            device_analysis = analysis_data.get("device_analysis", {})
            geo_analysis = analysis_data.get("geo_analysis", {})

            # AI-powered risk analysis using Ollama
            try:
                ai_analysis_result = await self._analyze_with_ai(user_id, analysis_data)
                if ai_analysis_result.get("success"):
                    base_score = ai_analysis_result.get("ai_risk_score", base_score)
                    ai_risk_factors = ai_analysis_result.get("ai_risk_factors", [])
                    risk_factors.extend(ai_risk_factors)
                    logger.info(f"AI analysis completed for user {user_id}: score {base_score}")
                else:
                    logger.warning(f"AI analysis failed for user {user_id}, falling back to rule-based")
            except Exception as e:
                logger.warning(f"AI analysis error for user {user_id}: {e}, falling back to rule-based")

            # Login pattern risk factors
            if login_analysis.get("success"):
                login_anomalies = login_analysis.get("anomalies", [])
                login_risk_factors = login_analysis.get("risk_factors", [])

                for factor in login_risk_factors:
                    severity = factor.get("severity", "low")
                    if severity == "high":
                        base_score += 0.3
                    elif severity == "medium":
                        base_score += 0.2
                    elif severity == "low":
                        base_score += 0.1

                anomalies.extend(login_anomalies)
                risk_factors.extend(login_risk_factors)

            # Device analysis risk factors
            if device_analysis.get("success"):
                device_anomalies = device_analysis.get("anomalies", [])
                device_risk_factors = device_analysis.get("risk_factors", [])

                for factor in device_risk_factors:
                    severity = factor.get("severity", "low")
                    if severity == "high":
                        base_score += 0.25
                    elif severity == "medium":
                        base_score += 0.15
                    elif severity == "low":
                        base_score += 0.05

                anomalies.extend(device_anomalies)
                risk_factors.extend(device_risk_factors)

            # Geographic analysis risk factors
            if geo_analysis.get("success"):
                geo_anomalies = geo_analysis.get("anomalies", [])
                geo_risk_factors = geo_analysis.get("risk_factors", [])

                for factor in geo_risk_factors:
                    severity = factor.get("severity", "low")
                    if severity == "high":
                        base_score += 0.4  # Location is very important
                    elif severity == "medium":
                        base_score += 0.25
                    elif severity == "low":
                        base_score += 0.1

                anomalies.extend(geo_anomalies)
                risk_factors.extend(geo_risk_factors)

            # Cap the score at 1.0
            final_score = min(base_score, 1.0)

            # Determine risk level
            if final_score >= 0.8:
                risk_level = "critical"
            elif final_score >= 0.6:
                risk_level = "high"
            elif final_score >= 0.4:
                risk_level = "medium"
            elif final_score >= 0.2:
                risk_level = "low"
            else:
                risk_level = "minimal"

            # Store risk assessment
            async with AsyncSessionLocal() as session:
                await session.execute(
                    text("""
                        INSERT INTO risk_scores
                        (user_id, risk_score, risk_level, risk_factors, anomalies, analysis_data, created_at)
                        VALUES (:user_id, :risk_score, :risk_level, :risk_factors, :anomalies, :analysis_data, :created_at)
                    """),
                    {
                        "user_id": user_id,
                        "risk_score": final_score,
                        "risk_level": risk_level,
                        "risk_factors": json.dumps(risk_factors),
                        "anomalies": json.dumps(anomalies),
                        "analysis_data": json.dumps(analysis_data),
                        "created_at": datetime.utcnow()
                    }
                )
                await session.commit()

            logger.info(f"Risk score calculated for user {user_id}: {final_score} ({risk_level})")

            return {
                "success": True,
                "user_id": user_id,
                "risk_score": final_score,
                "risk_level": risk_level,
                "risk_factors": risk_factors,
                "anomalies": anomalies,
                "ai_analysis": ai_analysis_result,
                "ai_enhanced": ai_analysis_result is not None and ai_analysis_result.get("success", False),
                "calculation_timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Error calculating risk score for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "user_id": user_id,
                "risk_score": 0.0
            }

    @activity.defn(name="detect_device_fingerprinting")
    async def detect_device_fingerprinting(self, user_id: str, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect device fingerprinting and analyze device patterns"""
        activity.logger.info(f"Analyzing device fingerprinting for user {user_id}")

        try:
            anomalies = []
            risk_factors = []

            # Extract device information from user agent
            user_agent_string = device_data.get("user_agent", "")
            if user_agent_string:
                parsed_ua = parse_user_agent(user_agent_string)
                device_info = {
                    "browser": f"{parsed_ua.browser.family} {parsed_ua.browser.version_string}",
                    "os": f"{parsed_ua.os.family} {parsed_ua.os.version_string}",
                    "device": parsed_ua.device.family if parsed_ua.device.family != "Other" else "Unknown",
                    "is_mobile": parsed_ua.is_mobile,
                    "is_tablet": parsed_ua.is_tablet,
                    "is_bot": parsed_ua.is_bot
                }

                # Check for bot detection
                if device_info.get("is_bot"):
                    anomalies.append("bot_detected")
                    risk_factors.append({"type": "bot_access", "severity": "high"})
            else:
                device_info = {}
                anomalies.append("missing_user_agent")
                risk_factors.append({"type": "no_user_agent", "severity": "medium"})

            # Create device fingerprint
            fingerprint = self._create_device_fingerprint(user_agent_string, device_data)

            # Check device history
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    text("""
                        SELECT DISTINCT device_fingerprint
                        FROM behavior_analytics
                        WHERE user_id = :user_id
                        AND created_at >= :since
                        AND device_fingerprint IS NOT NULL
                    """),
                    {
                        "user_id": user_id,
                        "since": datetime.utcnow() - timedelta(days=30)
                    }
                )

                known_devices = [json.loads(row[0]) if row[0] else {} for row in result.fetchall()]

                # Check if this is a new device
                current_fingerprint_data = {"fingerprint": fingerprint, **device_info}
                is_new_device = not any(
                    d.get("fingerprint") == fingerprint for d in known_devices
                )

                if is_new_device:
                    anomalies.append("new_device")
                    risk_factors.append({"type": "new_device", "severity": "medium"})

            logger.info(f"Device fingerprinting analysis completed for user {user_id}")

            return {
                "success": True,
                "user_id": user_id,
                "device_fingerprint": fingerprint,
                "device_info": device_info,
                "anomalies": anomalies,
                "risk_factors": risk_factors,
                "is_new_device": is_new_device,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Error analyzing device fingerprinting for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "user_id": user_id
            }

    @activity.defn(name="analyze_geolocation_patterns")
    async def analyze_geolocation_patterns(self, user_id: str, geolocation: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze geolocation patterns for anomaly detection"""
        activity.logger.info(f"Analyzing geolocation patterns for user {user_id}")

        try:
            anomalies = []
            risk_factors = []

            if not geolocation or not geolocation.get("latitude") or not geolocation.get("longitude"):
                return {
                    "success": True,
                    "user_id": user_id,
                    "anomalies": ["missing_geolocation"],
                    "risk_factors": [{"type": "no_location", "severity": "low"}],
                    "analysis_timestamp": datetime.utcnow().isoformat()
                }

            current_lat = float(geolocation["latitude"])
            current_lon = float(geolocation["longitude"])

            # Get location history
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    text("""
                        SELECT geolocation, timestamp
                        FROM behavior_analytics
                        WHERE user_id = :user_id
                        AND geolocation IS NOT NULL
                        AND created_at >= :since
                        ORDER BY created_at DESC
                        LIMIT 20
                    """),
                    {
                        "user_id": user_id,
                        "since": datetime.utcnow() - timedelta(days=30)
                    }
                )

                location_history = result.fetchall()

                if location_history:
                    # Analyze location patterns
                    distances = []
                    for row in location_history:
                        try:
                            historical_geo = json.loads(row[0]) if row[0] else {}
                            if historical_geo.get("latitude") and historical_geo.get("longitude"):
                                hist_lat = float(historical_geo["latitude"])
                                hist_lon = float(historical_geo["longitude"])
                                distance = self._calculate_distance(current_lat, current_lon, hist_lat, hist_lon)
                                distances.append(distance)
                        except (json.JSONDecodeError, ValueError):
                            continue

                    if distances:
                        min_distance = min(distances)
                        avg_distance = sum(distances) / len(distances)

                        # Check for impossible travel
                        if location_history and len(location_history) > 1:
                            try:
                                recent_geo = json.loads(location_history[0][0])
                                recent_timestamp = datetime.fromisoformat(location_history[0][1])
                                current_timestamp = datetime.utcnow()

                                if recent_geo.get("latitude") and recent_geo.get("longitude"):
                                    recent_lat = float(recent_geo["latitude"])
                                    recent_lon = float(recent_geo["longitude"])
                                    recent_distance = self._calculate_distance(
                                        current_lat, current_lon, recent_lat, recent_lon
                                    )

                                    time_diff_hours = (current_timestamp - recent_timestamp).total_seconds() / 3600
                                    if time_diff_hours > 0:
                                        max_possible_speed = recent_distance / time_diff_hours  # km/h

                                        # Check for impossible travel (faster than commercial aircraft)
                                        if max_possible_speed > 900:  # 900 km/h threshold
                                            anomalies.append("impossible_travel")
                                            risk_factors.append({
                                                "type": "impossible_travel",
                                                "severity": "critical",
                                                "distance_km": recent_distance,
                                                "time_hours": time_diff_hours,
                                                "speed_kmh": max_possible_speed
                                            })
                            except (json.JSONDecodeError, ValueError, TypeError):
                                pass

                        # Check for unusual location (far from normal pattern)
                        if min_distance > 500:  # More than 500km from any previous location
                            anomalies.append("unusual_location")
                            risk_factors.append({
                                "type": "location_anomaly",
                                "severity": "high",
                                "min_distance_km": min_distance
                            })
                        elif min_distance > 100:  # More than 100km but less than 500km
                            anomalies.append("distant_location")
                            risk_factors.append({
                                "type": "distant_location",
                                "severity": "medium",
                                "min_distance_km": min_distance
                            })
                else:
                    # First location record
                    risk_factors.append({"type": "first_location", "severity": "low"})

            logger.info(f"Geolocation analysis completed for user {user_id}")

            return {
                "success": True,
                "user_id": user_id,
                "current_location": {"latitude": current_lat, "longitude": current_lon},
                "anomalies": anomalies,
                "risk_factors": risk_factors,
                "location_history_count": len(location_history) if 'location_history' in locals() else 0,
                "analysis_timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Error analyzing geolocation patterns for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "user_id": user_id
            }

    @activity.defn(name="update_behavior_baseline")
    async def update_behavior_baseline(self, user_id: str, behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user's behavioral baseline with new data"""
        activity.logger.info(f"Updating behavior baseline for user {user_id}")

        try:
            async with AsyncSessionLocal() as session:
                # Get or create baseline record
                result = await session.execute(
                    text("""
                        SELECT baseline_data, updated_at
                        FROM user_baselines
                        WHERE user_id = :user_id
                    """),
                    {"user_id": user_id}
                )

                baseline_record = result.fetchone()

                if baseline_record:
                    # Update existing baseline
                    current_baseline = json.loads(baseline_record[0]) if baseline_record[0] else {}

                    # Merge new behavior data with weighted average
                    updated_baseline = self._update_baseline_metrics(current_baseline, behavior_data)

                    await session.execute(
                        text("""
                            UPDATE user_baselines
                            SET baseline_data = :baseline_data, updated_at = :updated_at
                            WHERE user_id = :user_id
                        """),
                        {
                            "user_id": user_id,
                            "baseline_data": json.dumps(updated_baseline),
                            "updated_at": datetime.utcnow()
                        }
                    )
                else:
                    # Create new baseline
                    initial_baseline = self._create_initial_baseline(behavior_data)

                    await session.execute(
                        text("""
                            INSERT INTO user_baselines
                            (user_id, baseline_data, created_at, updated_at)
                            VALUES (:user_id, :baseline_data, :created_at, :updated_at)
                        """),
                        {
                            "user_id": user_id,
                            "baseline_data": json.dumps(initial_baseline),
                            "created_at": datetime.utcnow(),
                            "updated_at": datetime.utcnow()
                        }
                    )

                await session.commit()

            logger.info(f"Behavior baseline updated successfully for user {user_id}")

            return {
                "success": True,
                "user_id": user_id,
                "baseline_updated": True,
                "update_timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Error updating behavior baseline for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "user_id": user_id
            }

    @activity.defn(name="trigger_fraud_alert")
    async def trigger_fraud_alert(self, user_id: str, risk_assessment: Dict[str, Any], session_id: str) -> Dict[str, Any]:
        """Trigger fraud alerts for high-risk activities"""
        activity.logger.info(f"Triggering fraud alert for user {user_id}")

        try:
            risk_score = risk_assessment.get("risk_score", 0.0)
            risk_level = risk_assessment.get("risk_level", "unknown")

            # Create fraud alert record
            alert_data = {
                "user_id": user_id,
                "session_id": session_id,
                "alert_type": "fraud_detection",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": json.dumps(risk_assessment.get("risk_factors", [])),
                "anomalies": json.dumps(risk_assessment.get("anomalies", [])),
                "status": "active",
                "severity": "high" if risk_score > 0.8 else "medium",
                "created_at": datetime.utcnow()
            }

            async with AsyncSessionLocal() as session:
                await session.execute(
                    text("""
                        INSERT INTO fraud_alerts
                        (user_id, session_id, alert_type, risk_score, risk_level,
                         risk_factors, anomalies, status, severity, created_at)
                        VALUES (:user_id, :session_id, :alert_type, :risk_score, :risk_level,
                                :risk_factors, :anomalies, :status, :severity, :created_at)
                    """),
                    alert_data
                )
                await session.commit()

            # Cache alert for real-time notifications
            redis_client = await self._get_redis()
            if redis_client:
                alert_cache = json.dumps({
                    "user_id": user_id,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "timestamp": datetime.utcnow().isoformat()
                })
                await redis_client.lpush("fraud_alerts:recent", alert_cache)
                await redis_client.ltrim("fraud_alerts:recent", 0, 99)  # Keep last 100 alerts
                await redis_client.expire("fraud_alerts:recent", 86400)  # 24 hours

            alerts_triggered = [
                {
                    "type": "fraud_detection",
                    "severity": alert_data["severity"],
                    "risk_score": risk_score,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]

            logger.info(f"Fraud alert triggered successfully for user {user_id}")

            return {
                "success": True,
                "user_id": user_id,
                "alerts": alerts_triggered,
                "alert_timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Error triggering fraud alert for user {user_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "user_id": user_id,
                "alerts": []
            }

    def _update_baseline_metrics(self, current_baseline: Dict[str, Any], new_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update baseline metrics with weighted average"""
        # Implementation of baseline update logic
        updated = current_baseline.copy()

        # Update frequency counters
        for key in ["ip_addresses", "user_agents", "locations", "login_times"]:
            if key in new_data and key in updated:
                # Merge with weighted average (70% current, 30% new)
                for item, count in new_data[key].items():
                    if item in updated[key]:
                        updated[key][item] = int(updated[key][item] * 0.7 + count * 0.3)
                    else:
                        updated[key][item] = count
            elif key in new_data:
                updated[key] = new_data[key]

        return updated

    def _create_initial_baseline(self, behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create initial baseline from first behavior data"""
        return {
            "ip_addresses": {behavior_data.get("ip_address", ""): 1},
            "user_agents": {behavior_data.get("user_agent", ""): 1},
            "locations": {},
            "login_times": {str(datetime.utcnow().hour): 1},
            "created_from": "initial_behavior",
            "version": "1.0"
        }

    async def _analyze_with_ai(self, user_id: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavior using AI/ML models via Ollama"""
        try:
            import httpx
            import json

            # Prepare data for AI analysis
            ai_input = {
                "user_id": user_id,
                "behavior_data": analysis_data.get("behavior_data", {}),
                "login_analysis": analysis_data.get("login_analysis", {}),
                "device_analysis": analysis_data.get("device_analysis", {}),
                "geo_analysis": analysis_data.get("geo_analysis", {}),
                "timestamp": datetime.utcnow().isoformat()
            }

            # Create a detailed prompt for the AI model
            ai_prompt = self._create_fraud_detection_prompt(ai_input)

            # Call Ollama API for fraud detection analysis
            async with httpx.AsyncClient(timeout=30.0) as client:
                try:
                    # Try with llama3 model first
                    response = await client.post(
                        "http://ollama:11434/api/generate",
                        json={
                            "model": "llama3",
                            "prompt": ai_prompt,
                            "stream": False,
                            "options": {
                                "temperature": 0.3,
                                "top_p": 0.9,
                                "num_predict": 500
                            }
                        }
                    )

                    if response.status_code == 200:
                        result = response.json()
                        ai_response = result.get("response", "")

                        # Parse AI response to extract risk score and factors
                        ai_analysis = self._parse_ai_response(ai_response)

                        logger.info(f"AI analysis successful for user {user_id}")
                        return {
                            "success": True,
                            "ai_risk_score": ai_analysis.get("risk_score", 0.0),
                            "ai_risk_factors": ai_analysis.get("risk_factors", []),
                            "ai_confidence": ai_analysis.get("confidence", 0.0),
                            "ai_reasoning": ai_analysis.get("reasoning", ""),
                            "model_used": "llama3",
                            "analysis_timestamp": datetime.utcnow().isoformat()
                        }

                except httpx.ConnectError:
                    # Fallback to local analysis if Ollama is not available
                    logger.warning("Ollama not available, using local AI analysis")

                except Exception as e:
                    logger.warning(f"Ollama request failed: {e}")

            # Local AI-like analysis as fallback
            return await self._local_ai_analysis(ai_input)

        except Exception as e:
            logger.error(f"AI analysis failed for user {user_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "fallback_used": True
            }

    def _create_fraud_detection_prompt(self, data: Dict[str, Any]) -> str:
        """Create a detailed prompt for fraud detection AI analysis"""

        behavior_data = data.get("behavior_data", {})
        login_analysis = data.get("login_analysis", {})
        device_analysis = data.get("device_analysis", {})
        geo_analysis = data.get("geo_analysis", {})

        prompt = f"""
You are an advanced fraud detection AI system. Analyze the following user behavior data and provide a risk assessment.

USER BEHAVIOR ANALYSIS:
- User ID: {data['user_id']}
- Event Type: {behavior_data.get('event_type', 'unknown')}
- IP Address: {behavior_data.get('ip_address', 'unknown')}
- Timestamp: {data['timestamp']}

LOGIN PATTERNS:
- Anomalies: {login_analysis.get('anomalies', [])}
- Risk Factors: {login_analysis.get('risk_factors', [])}
- Login History Count: {login_analysis.get('login_history_count', 0)}

DEVICE ANALYSIS:
- Device Anomalies: {device_analysis.get('anomalies', [])}
- Device Risk Factors: {device_analysis.get('risk_factors', [])}
- New Device: {device_analysis.get('is_new_device', False)}

GEOLOCATION ANALYSIS:
- Location Anomalies: {geo_analysis.get('anomalies', [])}
- Location Risk Factors: {geo_analysis.get('risk_factors', [])}

Based on this data, provide a JSON response with:
1. risk_score: A float between 0.0 and 1.0 (where 1.0 is highest risk)
2. confidence: Your confidence in this assessment (0.0 to 1.0)
3. reasoning: Brief explanation of your assessment
4. risk_factors: Array of key risk factors identified
5. recommendations: Array of recommended actions

Focus on detecting:
- Account takeover attempts
- Impossible travel scenarios
- Device spoofing
- IP reputation issues
- Behavioral anomalies
- Time-based patterns

Response must be valid JSON format.
"""
        return prompt

    def _parse_ai_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI response and extract structured data"""
        try:
            # Try to find JSON in the response
            import re

            # Look for JSON-like content
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                parsed = json.loads(json_str)

                return {
                    "risk_score": min(max(float(parsed.get("risk_score", 0.0)), 0.0), 1.0),
                    "confidence": min(max(float(parsed.get("confidence", 0.5)), 0.0), 1.0),
                    "reasoning": parsed.get("reasoning", "AI analysis completed"),
                    "risk_factors": parsed.get("risk_factors", []),
                    "recommendations": parsed.get("recommendations", [])
                }

            # Fallback: extract risk score from text
            risk_match = re.search(r'risk[_\s]*score[:\s]*([0-9.]+)', ai_response, re.IGNORECASE)
            if risk_match:
                risk_score = float(risk_match.group(1))
                return {
                    "risk_score": min(max(risk_score, 0.0), 1.0),
                    "confidence": 0.6,
                    "reasoning": "Extracted from AI text response",
                    "risk_factors": [],
                    "recommendations": []
                }

            # Default fallback
            return {
                "risk_score": 0.3,
                "confidence": 0.4,
                "reasoning": "Could not parse AI response, using default",
                "risk_factors": [],
                "recommendations": []
            }

        except Exception as e:
            logger.warning(f"Error parsing AI response: {e}")
            return {
                "risk_score": 0.2,
                "confidence": 0.3,
                "reasoning": f"Parse error: {str(e)}",
                "risk_factors": [],
                "recommendations": []
            }

    async def _local_ai_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Local AI-like analysis using heuristics when Ollama is not available"""
        try:
            behavior_data = data.get("behavior_data", {})
            login_analysis = data.get("login_analysis", {})
            device_analysis = data.get("device_analysis", {})
            geo_analysis = data.get("geo_analysis", {})

            risk_score = 0.0
            risk_factors = []

            # Analyze login patterns
            if login_analysis.get("anomalies"):
                for anomaly in login_analysis.get("anomalies", []):
                    if anomaly == "new_ip_address":
                        risk_score += 0.2
                        risk_factors.append({"type": "new_ip", "weight": 0.2})
                    elif anomaly == "unusual_location":
                        risk_score += 0.3
                        risk_factors.append({"type": "location_anomaly", "weight": 0.3})
                    elif anomaly == "unusual_time":
                        risk_score += 0.1
                        risk_factors.append({"type": "time_anomaly", "weight": 0.1})

            # Analyze device patterns
            if device_analysis.get("is_new_device"):
                risk_score += 0.15
                risk_factors.append({"type": "new_device", "weight": 0.15})

            # Analyze geo patterns
            if geo_analysis.get("anomalies"):
                for anomaly in geo_analysis.get("anomalies", []):
                    if anomaly == "impossible_travel":
                        risk_score += 0.4
                        risk_factors.append({"type": "impossible_travel", "weight": 0.4})
                    elif anomaly == "unusual_location":
                        risk_score += 0.25
                        risk_factors.append({"type": "location_risk", "weight": 0.25})

            # Cap the score
            risk_score = min(risk_score, 1.0)

            return {
                "success": True,
                "ai_risk_score": risk_score,
                "ai_risk_factors": risk_factors,
                "ai_confidence": 0.7,
                "ai_reasoning": "Local heuristic analysis (Ollama unavailable)",
                "model_used": "local_heuristic",
                "analysis_timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Local AI analysis failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }