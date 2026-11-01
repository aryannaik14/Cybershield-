# 🛡️ CyberShield – Cybersecurity Incident Analysis Dashboard

**A Python-powered defensive cybersecurity analytics project that detects brute-force login attacks, analyzes authentication events, and visualizes security incidents through an interactive Power BI dashboard.**

Developed by **Aryan Naik**  
LJIET, Ahmedabad  
*College Individual Project · Defensive Cybersecurity Analytics*

---

## 📌 1. Project Overview

CyberShield is a lightweight Security Operations Center (SOC) analytics platform designed to identify and analyze brute-force login attempts.

Brute-force attacks involve repeatedly attempting different passwords to gain unauthorized access to an account. These attacks can be difficult to identify when examining individual login records.

CyberShield addresses this problem by collecting authentication logs from synthetic simulations and a locally hosted Flask login application, processing the events using Python, detecting suspicious activity through an explainable rolling-window algorithm, and presenting the results through Power BI.

The system uses CSV files for data storage and processing, eliminating the need for a database at the current project scale.

**Project safety:** All data is either synthetic or generated through my own locally hosted application at `127.0.0.1`. No public websites or third-party accounts are targeted.

---

## 🎯 2. Project Objectives

1. Generate labelled synthetic authentication logs covering different attack scenarios.
2. Capture real login events from a locally hosted Flask application.
3. Detect brute-force attempts using a configurable rule-based detection algorithm.
4. Visualize authentication events, security alerts, and supporting evidence through Power BI.
5. Test the detection logic and document its limitations transparently.

---

## 🏗️ 3. System Architecture

CyberShield follows a sequential data-processing pipeline:

```text
             DATA SOURCES
                   |
          +--------+--------+
          |                 |
   Synthetic Generator   Flask Login App
          |                 |
          +--------+--------+
                   |
                   v
              DATA LOADER
          - Validation
          - Normalization
          - Rejected records
          - Event merging
                   |
                   v
           UNIFIED EVENT LOGS
          unified_events.csv
                   |
                   v
          BRUTE-FORCE DETECTOR
          - Rolling time window
          - IP and username grouping
          - Threshold evaluation
          - Severity classification
                   |
                   v
             OUTPUT FILES
          - alerts.csv
          - alert_evidence.csv
          - rejected_records.csv
                   |
                   v
             POWER BI
          +--------------------+
          | 1. Security Overview|
          | 2. Brute-Force      |
          |    Detection        |
          | 3. Incident         |
          |    Investigation    |
          +--------------------+
```

The complete pipeline is executed through a single command:

```bash
python run_pipeline.py
```

This runs the generation, loading, validation, and detection stages.

---

## ⚙️ 4. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Data processing and detection logic |
| Flask | Local authentication application |
| CSV | Event and alert storage |
| Power BI | Security analytics and visualization |
| DAX | Dashboard calculations and evidence filtering |
| Power Query | Data loading and transformation |

---

## 📂 5. Data Sources and Event Schema

CyberShield uses two authentication event sources.

### A. Synthetic Data

- Generates fake users and authentication events.
- Includes seven designed attack scenarios.
- Uses reserved documentation IP ranges.
- Demo usernames carry a `_demo` suffix.

### B. Local Lab Data

- Captured from a locally hosted Flask login application.
- Runs exclusively on `127.0.0.1`.
- Generates actual authentication events from local testing.
- Does not expose the application to public networks.

### Unified Event Schema

Both sources follow the same seven-column structure:

| Column | Description |
|---|---|
| `timestamp_utc` | Event timestamp in UTC (ISO 8601) |
| `source_ip` | IP address associated with the attempt |
| `username` | Account name in lowercase |
| `event_type` | Type of event (`login_attempt`) |
| `outcome` | Authentication result (`success` or `failure`) |
| `source_type` | Event origin (`synthetic` or `local_lab`) |
| `environment` | Execution environment (`simulation` or `localhost_lab`) |

The loader also generates an `event_id` when merging events.

---

## 🔍 6. Data Validation and Normalization

The data loader validates incoming records before they enter the detection pipeline.

**Rejected records include:**
- Invalid timestamps.
- Invalid IP addresses.
- Unsafe usernames.
- Contradictory event labels.

Rejected records are stored in:

```text
rejected_records.csv
```

Each rejected record includes a reason.

**Normalization includes:**
- Converting timestamps to UTC.
- Converting usernames to lowercase.
- Sorting and numbering records.
- Neutralizing spreadsheet formulas in text fields.

**Important design decision:** Duplicate events are not removed. Two identical records can represent two genuine login attempts occurring in the same second. Removing them could hide attack activity.

---

## 🚨 7. Brute-Force Detection Algorithm

CyberShield uses an explainable, configurable rolling-window detection rule.

### Detection Rule

**5 failed login attempts within 5 minutes.**

Detection is performed separately for each combination of:

- Source IP address.
- Username.
- Source type.

Both the failure threshold and time window are configurable.

### Detection Process

1. Only failed authentication events are counted.
2. Events are processed in timestamp order.
3. A rolling five-minute window evaluates the number of failures.
4. An alert is generated when the configured threshold is reached.
5. One alert is generated per burst rather than repeatedly alerting for every additional failure.
6. Supporting evidence is retained for investigation.

### Severity Classification

| Severity | Condition |
|---|---|
| Low | 5–9 failed attempts |
| Medium | 10–14 failed attempts |
| High | 15 or more failed attempts |
| High | A successful login follows the failures |

A successful login following repeated failures increases the alert severity to High because it may indicate account compromise.

### Why a Rolling Window?

A rolling window helps identify concentrated authentication failures within a short period rather than simply counting failures across an entire day.

The five-minute window is inclusive:

- Five failures spanning exactly 300 seconds trigger detection.
- Five failures spanning 301 seconds do not satisfy the same window condition.

Each failure belongs to at most one alert.

---

## 🧪 8. Testing and Results

The detector was tested against seven deliberately designed synthetic scenarios using sample dataset seed `42`.

| Test Scenario | Expected Result |
|---|---|
| 14 fast failures | Alert – Medium |
| 8 failures followed by success | Alert – High |
| Exactly 5 failures | Alert – Low |
| Repeat offender with 9 failures | Alert – Low |
| 4 failures (near miss) | No alert |
| Slow attacker (2.5 minutes apart) | No alert |
| Password spraying across 10 users | No alert |

### Test Summary

**4 out of 7 designed attack scenarios detected.**

The remaining three scenarios are intentionally missed by the current detection rule. These results demonstrate the strengths and limitations of a simple threshold-based detection approach.

---

## 📊 9. Power BI Dashboard

CyberShield includes a three-page Power BI dashboard that transforms processed authentication logs into actionable security insights.

### Page 1 – Security Overview

Provides a high-level summary of authentication activity.

Key visualizations:
- Total Events.
- Failed Logins.
- Successful Logins.
- Total Alerts.
- High-Severity Alerts.
- Failed and successful login trends.
- Success versus failure distribution.
- Synthetic versus local-lab event distribution.
- Date and source filters.
- Data quality and refresh indicators.

### Page 2 – Brute-Force Detection

Focuses on identifying suspicious authentication patterns.

Key visualizations:
- Alerts by source IP.
- Alerts by username.
- Alerts by severity.
- Failed attempts within detection windows.
- Alert timeline.
- Detailed security alert table.
- Source, date, username, and severity filters.

### Page 3 – Incident Investigation

Allows an analyst to investigate a specific alert and examine the events that triggered it.

Key capabilities:
- Select an individual alert ID.
- View associated IP address and username.
- Examine alert severity and failed attempts.
- Analyze the failed-login timeline.
- View supporting evidence events.
- Navigate from an alert on Page 2 using drill-through functionality.

### Sample Dashboard Results

| Metric | Sample Result |
|---|---:|
| Total Events | 359 |
| Successful Logins | 243 |
| Failed Logins | 116 |
| Total Alerts | 6 |
| High-Severity Alerts | 2 |

*These values represent the sample dataset, not live monitoring results.*

**Dashboard refresh:** Power BI reads the processed CSV files. After running the Python pipeline, the user must manually select Refresh in Power BI to load the updated data.

---

## 🔐 10. Security Measures in the Local Login Application

The Flask login application includes several safeguards:

| Security Measure | Implementation |
|---|---|
| Localhost restriction | Fixed host: `127.0.0.1` |
| Debug mode | Disabled |
| IP validation | Forged IP headers ignored |
| Password handling | Passwords hashed, never logged |
| CSRF protection | Session-based form tokens |
| Rate limiting | Maximum 20 POST requests per 60 seconds |
| Input validation | Strict username pattern and size limits |
| Timestamp handling | UTC timestamps |

The local application is designed for controlled defensive testing, not public deployment.

---

## ⚠️ 11. Limitations

CyberShield is an educational defensive cybersecurity analytics project. It is not a production-grade SIEM or an automated incident-response platform.

Known limitations include:

**Detection limitations**
- Slow attacks with failures spread across longer periods can be missed.
- Four failures remain below the configured threshold.
- Password spraying across multiple usernames can evade per-user detection.
- Distributed attacks across multiple IP addresses can evade per-IP detection.

**Operational limitations**
- False positives can occur when legitimate users repeatedly enter incorrect passwords.
- Local application events originate from `127.0.0.1`, limiting per-IP differentiation in local testing.
- CSV-based processing requires manual Power BI refresh.
- Alerts are generated for analysis; the system does not automatically block IP addresses or accounts.

These limitations are documented to make the detection results transparent and identify possible future improvements.

---

## 🚀 12. Running the Project

### Prerequisites

- Python environment.
- Project source code.
- Power BI Desktop for dashboard visualization.

### Run the pipeline

From the project root directory:

```bash
python run_pipeline.py
```

The pipeline executes:
1. Synthetic event generation.
2. Event loading and validation.
3. Data normalization and merging.
4. Brute-force detection.
5. Alert and supporting-evidence generation.

### View the Dashboard

1. Open the CyberShield Power BI report (`CyberShield.pbix`).
2. Ensure its data-folder parameter points to the processed CSV directory.
3. Run the Python pipeline.
4. Open Power BI Desktop.
5. Select **Home → Refresh**.
6. Explore the three dashboard pages.

*Note: The dashboard is snapshot-based and does not provide real-time streaming.*

---

## 🔮 13. Future Enhancements

Potential improvements include:

- Detecting password spraying across multiple usernames.
- Identifying distributed brute-force attempts across multiple IP addresses.
- Adding adaptive detection thresholds.
- Introducing additional authentication attack scenarios.
- Supporting more event sources.
- Adding automated alert notifications.
- Exploring real-time event ingestion and monitoring.
- Improving incident investigation and evidence correlation.

---

## 👨‍💻 14. Author

**Aryan Naik**

Computer Science & Technology Student  
Lok Jagruti University (LJIET), Ahmedabad

Interested in:
- Defensive Cybersecurity
- Security Operations Center (SOC)
- Threat Detection and Analysis
- Incident Response
- Security Analytics

---

## 📜 15. Disclaimer

CyberShield was developed strictly for educational and defensive cybersecurity purposes.

All synthetic testing uses generated data, and all local authentication testing is conducted using the developer's own application on `127.0.0.1`.

This project does not target public systems, third-party accounts, or unauthorized networks.

---

**CyberShield – Turning Raw Security Logs into Actionable Threat Intelligence.**
