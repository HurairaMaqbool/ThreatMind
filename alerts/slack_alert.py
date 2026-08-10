import os
import requests
from utils.logger import logger
from pipeline.state import ThreatState

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:8501")


def send_slack_alert(state: ThreatState, feed_name: str):
    severity = state.get("severity_level", "LOW")

    if severity not in ["CRITICAL", "HIGH"]:
        return

    webhook_url = SLACK_WEBHOOK_URL or DISCORD_WEBHOOK_URL
    if not webhook_url:
        logger.warning("Neither SLACK_WEBHOOK_URL nor DISCORD_WEBHOOK_URL set. Skipping webhook alert.")
        return

    emoji = "🚨" if severity == "CRITICAL" else "⚠️"
    article_title = state.get("article_title", "Unknown")
    iocs = state.get("iocs", {})
    actor = iocs.get("threat_actor", "Unknown")
    cves = ", ".join(iocs.get("cve_numbers", [])) or "None"

    behaviors = state.get("behaviors", [])
    techniques = ", ".join(
        list({b.get("attack_technique") for b in behaviors if b.get("attack_technique")})
    )

    query_count = len(state.get("validated_queries", []))
    coverage = state.get("overall_coverage", "unknown")

    is_discord = "discord.com" in webhook_url or bool(DISCORD_WEBHOOK_URL and not SLACK_WEBHOOK_URL)

    if is_discord:
        discord_payload = {
            "content": f"{emoji} **[{severity}] AutoThreat Alert**: {article_title}",
            "embeds": [
                {
                    "title": article_title,
                    "description": f"**Actor**: {actor}\n**Source**: {feed_name}\n**CVEs**: {cves}\n**MITRE**: {techniques}\n**Queries Generated**: {query_count}\n**Coverage**: {coverage}",
                    "url": DASHBOARD_URL,
                    "color": 15158332 if severity == "CRITICAL" else 15105570,
                }
            ],
        }
        try:
            res = requests.post(webhook_url, json=discord_payload, timeout=15)
            if res.status_code in (200, 204):
                logger.info(f"Discord alert sent for {article_title}")
            else:
                logger.error(f"Discord alert failed: {res.text}")
        except Exception as e:
            logger.error(f"Discord error: {e}")
    else:
        slack_payload = {
            "text": f"{emoji} [{severity}] AutoThreat: New Threat Detected",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} [{severity}] New Threat Detected"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Source:*\n{feed_name}"},
                        {"type": "mrkdwn", "text": f"*Threat:*\n{article_title}"},
                        {"type": "mrkdwn", "text": f"*Actor:*\n{actor}"},
                        {"type": "mrkdwn", "text": f"*CVEs:*\n{cves}"},
                        {"type": "mrkdwn", "text": f"*MITRE:*\n{techniques}"},
                        {"type": "mrkdwn", "text": f"*Queries:*\n{query_count} generated"},
                        {"type": "mrkdwn", "text": f"*Coverage:*\n{coverage}"},
                    ],
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View Dashboard"},
                            "url": DASHBOARD_URL,
                            "style": "primary",
                        }
                    ],
                },
            ],
        }
        try:
            response = requests.post(webhook_url, json=slack_payload, timeout=15)
            if response.status_code == 200:
                logger.info(f"Slack alert sent for {article_title}")
            else:
                logger.error(f"Slack alert failed: {response.text}")
        except Exception as e:
            logger.error(f"Slack error: {e}")
