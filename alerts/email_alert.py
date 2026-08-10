import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from utils.logger import logger
from pipeline.state import ThreatState

DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:8501")


def send_email_alert(state: ThreatState):
    severity = state.get("severity_level", "LOW")
    if severity == "LOW":
        return

    SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 25))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USER or "autothreat@localhost")
    EMAIL_TO = os.getenv("EMAIL_TO") or os.getenv("ALERT_EMAIL", "soc@localhost")

    if not SMTP_HOST or SMTP_HOST == "localhost":
        if not SMTP_USER:
            logger.warning("SMTP not configured. Skipping email alert.")
            return

    threat_name = state.get("article_title", "Unknown Threat")
    query_count = len(state.get("validated_queries", []))
    subject = f"🚨 [{severity}] AutoThreat: {threat_name} — {query_count} KQL Queries Ready"
    report_md = state.get("final_report", "No report available.")

    try:
        import markdown

        html_content = markdown.markdown(report_md, extensions=["tables", "fenced_code"])
    except Exception as e:
        logger.warning(f"Markdown conversion failed: {e}")
        html_content = f"<pre>{report_md}</pre>"

    body_html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            pre {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            code {{ font-family: Consolas, monospace; }}
            .btn {{ display: inline-block; padding: 10px 20px; background-color: #007bff; color: #fff; text-decoration: none; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <div style="margin-bottom: 20px;">
            <a href="{DASHBOARD_URL}" class="btn">View Dashboard</a>
        </div>
        {html_content}
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO

    part = MIMEText(body_html, "html")
    msg.attach(part)

    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
        if SMTP_USER and SMTP_PASSWORD:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        server.quit()
        logger.info(f"Email alert sent to {EMAIL_TO}")
    except Exception as e:
        logger.warning(f"Email sending failed: {e}")
