# CyberShield: Power BI setup guide

This guide builds a 3-page Power BI Desktop report from the CSV files that the
CyberShield pipeline writes.

> **The dashboard is NOT live.** Power BI reads the CSV files only when you
> press **Refresh**. After every `python run_pipeline.py` run, open the report
> and click **Home > Refresh**. Nothing refreshes automatically.

Requirements: Power BI Desktop (free, Windows only). On macOS or Linux, use a
Windows machine or virtual machine; the CSV files themselves are portable.

All times in the data are **UTC**. The report shows UTC; it does not convert to
your local time zone.

---

## 1. Before you start

1. Generate data. Pick ONE folder for Power BI to read:

   | Folder | Created by | Use it for |
   |---|---|---|
   | `data\sample\` | `python make_sample_data.py` | first build, screenshots, anyone who cloned the repo |
   | `data\processed\` | `python run_pipeline.py` | your own live runs |

2. Make sure that folder contains `unified_events.csv`, `alerts.csv`,
   `alert_evidence.csv` and `rejected_records.csv`.
3. Close those CSV files in Excel (Windows locks open files).
4. Turn off automatic relationship detection (we create relationships by hand):
   **File > Options and settings > Options > Current File > Data Load**, then
   untick **Autodetect new relationships after data is loaded**.

## 2. Import the data

### 2.1 Create the folder parameter

1. **Home > Transform data** (opens Power Query Editor).
2. **Home > Manage Parameters > New Parameter**.
3. Name: `DataFolder`. Type: `Text`. Current Value: the full path of your chosen
   folder, for example `C:\Users\YourName\Documents\cybershield\data\sample\`
4. Click OK.

To switch between sample and live data later, change this one value
(**Transform data > Edit parameters**) and refresh.

### 2.2 Create the queries

For each query below: **Home > New Source > Blank Query**, then
**Home > Advanced Editor**, delete everything, paste the code, click **Done**,
and rename the query (right-click the query name in the left list > Rename).

If a yellow bar asks about **data privacy levels**, choose **Ignore privacy
levels** (or set the files to Organizational). These are your own local files.

**Query 1, name it `Events`**

```m
let
    Folder = if Text.EndsWith(DataFolder, "\") then DataFolder else DataFolder & "\",
    Source = Csv.Document(File.Contents(Folder & "unified_events.csv"), [Delimiter = ",", Columns = 8, Encoding = 65001, QuoteStyle = QuoteStyle.Csv]),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),
    Typed = Table.TransformColumnTypes(Promoted, {
        {"event_id", Int64.Type}, {"timestamp_utc", type text}, {"source_ip", type text},
        {"username", type text}, {"event_type", type text}, {"outcome", type text},
        {"source_type", type text}, {"environment", type text}}),
    ToUtc = Table.TransformColumns(Typed, {{"timestamp_utc",
        each DateTimeZone.RemoveZone(DateTimeZone.SwitchZone(DateTimeZone.FromText(_), 0)),
        type datetime}}),
    AddDate = Table.AddColumn(ToUtc, "Event Date", each Date.From([timestamp_utc]), type date),
    AddHour = Table.AddColumn(AddDate, "Event Hour",
        each DateTime.From(Date.From([timestamp_utc])) + #duration(0, Time.Hour([timestamp_utc]), 0, 0),
        type datetime),
    AddMinute = Table.AddColumn(AddHour, "Event Minute",
        each DateTime.From(Date.From([timestamp_utc])) + #duration(0, Time.Hour([timestamp_utc]), Time.Minute([timestamp_utc]), 0),
        type datetime)
in
    AddMinute
```

**Query 2, name it `Alerts`**

```m
let
    Folder = if Text.EndsWith(DataFolder, "\") then DataFolder else DataFolder & "\",
    Source = Csv.Document(File.Contents(Folder & "alerts.csv"), [Delimiter = ",", Columns = 14, Encoding = 65001, QuoteStyle = QuoteStyle.Csv]),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),
    Typed = Table.TransformColumnTypes(Promoted, {
        {"alert_id", type text}, {"alert_time_utc", type text}, {"source_ip", type text},
        {"username", type text}, {"attempt_count", Int64.Type}, {"window_start_utc", type text},
        {"window_end_utc", type text}, {"window_minutes", type number}, {"threshold", Int64.Type},
        {"severity", type text}, {"success_after_failures", type text}, {"alert_type", type text},
        {"source_type", type text}, {"environment", type text}}),
    ToUtc = Table.TransformColumns(Typed, {
        {"alert_time_utc", each DateTimeZone.RemoveZone(DateTimeZone.SwitchZone(DateTimeZone.FromText(_), 0)), type datetime},
        {"window_start_utc", each DateTimeZone.RemoveZone(DateTimeZone.SwitchZone(DateTimeZone.FromText(_), 0)), type datetime},
        {"window_end_utc", each DateTimeZone.RemoveZone(DateTimeZone.SwitchZone(DateTimeZone.FromText(_), 0)), type datetime}}),
    AddDate = Table.AddColumn(ToUtc, "Alert Date", each Date.From([alert_time_utc]), type date),
    AddRank = Table.AddColumn(AddDate, "Severity Rank",
        each if [severity] = "low" then 1 else if [severity] = "medium" then 2 else if [severity] = "high" then 3 else null,
        Int64.Type)
in
    AddRank
```

**Query 3, name it `AlertEvidence`**

```m
let
    Folder = if Text.EndsWith(DataFolder, "\") then DataFolder else DataFolder & "\",
    Source = Csv.Document(File.Contents(Folder & "alert_evidence.csv"), [Delimiter = ",", Columns = 2, Encoding = 65001, QuoteStyle = QuoteStyle.Csv]),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),
    Typed = Table.TransformColumnTypes(Promoted, {{"alert_id", type text}, {"event_id", Int64.Type}})
in
    Typed
```

**Query 4, name it `RejectedRecords`** (data-quality card only; no relationships)

```m
let
    Folder = if Text.EndsWith(DataFolder, "\") then DataFolder else DataFolder & "\",
    Source = Csv.Document(File.Contents(Folder & "rejected_records.csv"), [Delimiter = ",", Columns = 4, Encoding = 65001, QuoteStyle = QuoteStyle.Csv]),
    Promoted = Table.PromoteHeaders(Source, [PromoteAllScalars = true]),
    Typed = Table.TransformColumnTypes(Promoted, {
        {"source_file", type text}, {"line_number", Int64.Type},
        {"reject_reason", type text}, {"raw_record", type text}})
in
    Typed
```

**Query 5, name it `RefreshInfo`** (records WHEN you last pressed Refresh)

```m
let
    Source = #table(type table [Refreshed_UTC = datetime],
        {{DateTimeZone.RemoveZone(DateTimeZone.SwitchZone(DateTimeZone.FixedUtcNow(), 0))}})
in
    Source
```

Then **Home > Close & Apply**.

> Before closing, check each query's last step has no red error. If a query
> shows `DataSource.NotFound`, your `DataFolder` path is wrong.

## 3. Build the model

### 3.1 Calculated tables

In Report view or Data view: **Modeling > New table**, one at a time.

```dax
DimDate = CALENDAR ( MIN ( Events[Event Date] ), MAX ( Events[Event Date] ) )
```

```dax
DimSourceType = DISTINCT ( Events[source_type] )
```

```dax
DimUsername = DISTINCT ( Events[username] )
```

```dax
DimSourceIP = DISTINCT ( Events[source_ip] )
```

Select `DimDate`, then **Table tools > Mark as date table**, using the `Date` column.

These small "dimension" tables are shared filters. They let ONE slicer filter
both the Events table and the Alerts table.

### 3.2 Relationships

Open **Model view**. Delete any relationship that Power BI created by itself
(especially `Events[event_id]` to `AlertEvidence[event_id]`: it would create
an ambiguous path). Then create these by dragging the first column onto the second:

| From (one side) | To (many side) | Cardinality | Filter direction |
|---|---|---|---|
| `DimDate[Date]` | `Events[Event Date]` | One to many | Single |
| `DimDate[Date]` | `Alerts[Alert Date]` | One to many | Single |
| `DimSourceType[source_type]` | `Events[source_type]` | One to many | Single |
| `DimSourceType[source_type]` | `Alerts[source_type]` | One to many | Single |
| `DimUsername[username]` | `Events[username]` | One to many | Single |
| `DimUsername[username]` | `Alerts[username]` | One to many | Single |
| `DimSourceIP[source_ip]` | `Events[source_ip]` | One to many | Single |
| `DimSourceIP[source_ip]` | `Alerts[source_ip]` | One to many | Single |
| `Alerts[alert_id]` | `AlertEvidence[alert_id]` | One to many | Single |

`Events` and `AlertEvidence` are deliberately NOT related by a line. The link
between an alert and its evidence events is done by the measures in section 4,
which avoids a two-path ambiguity in the model.

`RejectedRecords` and `RefreshInfo` have no relationships.

### 3.3 Column settings

* `Alerts[severity]`: select it, then **Column tools > Sort by column > Severity Rank**
  (so severity sorts low, medium, high instead of alphabetically).
* Set the display format of every datetime column
  (`Events[timestamp_utc]`, `Alerts[alert_time_utc]`, `window_start_utc`,
  `window_end_utc`, `Event Hour`, `Event Minute`, `RefreshInfo[Refreshed_UTC]`) to
  `yyyy-mm-dd hh:mm:ss` (**Column tools > Format > Custom**).
* `Alerts[window_minutes]` and `threshold`: Summarization `Don't summarize`.
* Use the `Dim*` fields (not the same-named fields in `Events` or `Alerts`) for slicers.

## 4. DAX measures

Create each with **Modeling > New measure** (right-click a table > New measure).
The table to put it in is shown above each block. Names are used by the pages
in section 5, so copy them exactly.

### 4.1 Table `Events`

```dax
Total Events = COUNTROWS ( Events ) + 0
```

```dax
Failed Logins = CALCULATE ( COUNTROWS ( Events ), Events[outcome] = "failure" ) + 0
```

```dax
Successful Logins = CALCULATE ( COUNTROWS ( Events ), Events[outcome] = "success" ) + 0
```

```dax
Failure Rate = DIVIDE ( [Failed Logins], [Total Events] )
```

```dax
Synthetic Events = CALCULATE ( COUNTROWS ( Events ), Events[source_type] = "synthetic" ) + 0
```

```dax
Local Lab Events = CALCULATE ( COUNTROWS ( Events ), Events[source_type] = "local_lab" ) + 0
```

```dax
Unique Source IPs = DISTINCTCOUNT ( Events[source_ip] )
```

```dax
Unique Usernames = DISTINCTCOUNT ( Events[username] )
```

```dax
Latest Event UTC = MAX ( Events[timestamp_utc] )
```

Set `Failure Rate` to format Percentage (1 decimal).

### 4.2 Table `Alerts`

```dax
Total Alerts = COUNTROWS ( Alerts ) + 0
```

```dax
High Severity Alerts = CALCULATE ( COUNTROWS ( Alerts ), Alerts[severity] = "high" ) + 0
```

```dax
Medium Severity Alerts = CALCULATE ( COUNTROWS ( Alerts ), Alerts[severity] = "medium" ) + 0
```

```dax
Low Severity Alerts = CALCULATE ( COUNTROWS ( Alerts ), Alerts[severity] = "low" ) + 0
```

```dax
Alerts With Success After = CALCULATE ( COUNTROWS ( Alerts ), Alerts[success_after_failures] = "yes" ) + 0
```

```dax
Failed Attempts In Alert Windows = SUM ( Alerts[attempt_count] )
```

```dax
Average Attempts Per Alert = DIVIDE ( [Failed Attempts In Alert Windows], COUNTROWS ( Alerts ) )
```

```dax
Largest Burst = MAX ( Alerts[attempt_count] )
```

### 4.3 Table `Alerts` (investigation page, selected-alert cards)

```dax
Selected Alert = SELECTEDVALUE ( Alerts[alert_id], "Select one alert" )
```

```dax
Selected Source IP = SELECTEDVALUE ( Alerts[source_ip], "Multiple" )
```

```dax
Selected Username = SELECTEDVALUE ( Alerts[username], "Multiple" )
```

```dax
Selected Severity = SELECTEDVALUE ( Alerts[severity], "Multiple" )
```

```dax
Selected Window Start UTC = SELECTEDVALUE ( Alerts[window_start_utc] )
```

```dax
Selected Window End UTC = SELECTEDVALUE ( Alerts[window_end_utc] )
```

```dax
Selected Success After = SELECTEDVALUE ( Alerts[success_after_failures], "Multiple" )
```

Format the two window measures as `yyyy-mm-dd hh:mm:ss`.

### 4.4 Table `AlertEvidence` (links alerts to their events)

These work without a relationship line. `VALUES ( AlertEvidence[event_id] )` is
the set of event numbers that support the alerts currently selected or filtered.

```dax
Is Evidence Event =
VAR ThisEvent = SELECTEDVALUE ( Events[event_id] )
RETURN
    IF ( NOT ISBLANK ( ThisEvent ) && ThisEvent IN VALUES ( AlertEvidence[event_id] ), 1, 0 )
```

```dax
Evidence Events =
SUMX (
    VALUES ( Events[event_id] ),
    IF ( Events[event_id] IN VALUES ( AlertEvidence[event_id] ), 1, 0 )
)
```

```dax
Evidence Failed Logins = CALCULATE ( [Evidence Events], Events[outcome] = "failure" )
```

```dax
Evidence Successful Logins = CALCULATE ( [Evidence Events], Events[outcome] = "success" )
```

```dax
Alert IDs For Event =
VAR ThisEvent = SELECTEDVALUE ( Events[event_id] )
RETURN
    CONCATENATEX (
        CALCULATETABLE ( VALUES ( AlertEvidence[alert_id] ), AlertEvidence[event_id] = ThisEvent ),
        AlertEvidence[alert_id],
        ", "
    )
```

```dax
Evidence Role =
VAR ThisEvent = SELECTEDVALUE ( Events[event_id] )
VAR IsEvidence = ThisEvent IN VALUES ( AlertEvidence[event_id] )
RETURN
    IF (
        ISBLANK ( ThisEvent ), BLANK (),
        IF ( IsEvidence,
            IF ( SELECTEDVALUE ( Events[outcome] ) = "success", "Success after failures", "Failed attempt in alert" ),
            "Context only" )
    )
```

### 4.5 Table `RefreshInfo` and `RejectedRecords`

```dax
Last Refresh UTC = MAX ( RefreshInfo[Refreshed_UTC] )
```

```dax
Rejected Records = COUNTROWS ( RejectedRecords ) + 0
```

## 5. Report pages

Use a plain light theme, a 16:9 canvas, and one font. Do not rely on colour
alone: label values directly. Suggested severity colours: low `#E0B000`,
medium `#E07B00`, high `#C0262D`. Name the pages exactly as below.

### Page 1: Security Overview

| Visual | Type | Fields |
|---|---|---|
| Total events | Card | `Total Events` |
| Failed logins | Card | `Failed Logins` |
| Successful logins | Card | `Successful Logins` |
| Total alerts | Card | `Total Alerts` |
| High-severity alerts | Card | `High Severity Alerts` |
| Event trend | Line chart | X: `DimDate[Date]`; Y: `Failed Logins`, `Successful Logins` |
| Success vs failure | Donut | Legend: `Events[outcome]`; Values: `Total Events` |
| Synthetic vs local lab | Clustered bar | Axis: `Events[source_type]`; Values: `Total Events`; data labels ON |
| Date filter | Slicer (Between) | `DimDate[Date]` |
| Source filter | Slicer (list) | `DimSourceType[source_type]` |
| Data quality | Card (small) | `Rejected Records` |
| Freshness | Text box + 2 cards | `Last Refresh UTC`, `Latest Event UTC`, plus the text "Not live: press Refresh after each pipeline run" |

Use a bar chart, not a pie, for synthetic vs local lab: the local-lab count is
tiny next to synthetic, and a pie would hide it.

### Page 2: Brute-Force Detection

| Visual | Type | Fields |
|---|---|---|
| Alerts by source IP | Bar chart | Axis: `Alerts[source_ip]`; Values: `Total Alerts` |
| Alerts by username | Bar chart | Axis: `Alerts[username]`; Values: `Total Alerts` |
| Alerts by severity | Column chart | Axis: `Alerts[severity]`; Values: `Total Alerts`; colour by severity |
| Failed attempts within detection windows | Bar chart | Axis: `Alerts[alert_id]`; Values: `Failed Attempts In Alert Windows`; tooltips: `window_start_utc`, `window_end_utc`, `threshold`, `window_minutes` |
| Alert timeline | Stacked column | Axis: `Alerts[Alert Date]`; Values: `Total Alerts`; Legend: `Alerts[severity]` |
| Alert list | Table | `alert_id`, `alert_time_utc`, `source_ip`, `username`, `attempt_count`, `severity`, `success_after_failures`, `source_type` |
| Filters | Four slicers | `DimSourceType[source_type]`, `DimDate[Date]` (Between), `DimUsername[username]`, `Alerts[severity]` |
| KPI strip (optional) | Cards | `Total Alerts`, `Failed Attempts In Alert Windows`, `Largest Burst`, `Alerts With Success After` |

### Page 3: Incident Investigation

1. On Page 3, open **Visualizations > Build visual** and under **Drill through**
   drag `Alerts[alert_id]` into **Add drill-through fields here**. From Page 2 you can now
   right-click an alert row > **Drill through > Incident Investigation**.

| Visual | Type | Fields |
|---|---|---|
| Choose an alert | Slicer (list), single select ON, Select all OFF | `Alerts[alert_id]` |
| Narrow by IP / user | Two slicers (dropdown) | `DimSourceIP[source_ip]`, `DimUsername[username]` |
| Selected alert details | Four cards | `Selected Alert`, `Selected Source IP`, `Selected Username`, `Selected Severity` |
| Window cards | Two cards | `Selected Window Start UTC`, `Selected Window End UTC` |
| Evidence counts | Cards | `Evidence Failed Logins`, `Evidence Successful Logins`, `Selected Success After` |
| Failed-login timeline | Column chart, continuous X axis | X: `Events[Event Minute]`; Y: `Failed Logins`, `Evidence Failed Logins` |
| Supporting evidence | Table | `Events[event_id]`, `Events[timestamp_utc]`, `source_ip`, `username`, `outcome`, `source_type`, measure `Evidence Role`; visual-level filter: `Is Evidence Event` is `1` |
| All events for the IP/user | Table | `Events[event_id]`, `timestamp_utc`, `source_ip`, `username`, `outcome`, `source_type`, `Alert IDs For Event`, `Evidence Role` (sort by `timestamp_utc`) |

How it behaves:
* Pick an IP and username with the dropdowns: the "All events" table and the timeline show that pair.
* Pick one alert: the cards fill in, and the "Supporting evidence" table shows
  exactly the events that caused it (the failures, plus the following success if any).
* With no alert selected, "Supporting evidence" lists events that belong to ANY visible alert.

### Slicers across pages

**View > Sync slicers** lets one slicer drive several pages. Sync the Date,
Source and Username slicers across all three pages. Keep the severity and alert
slicers on their own pages.

## 6. Refreshing and saving

1. Run `python run_pipeline.py` (or `python make_sample_data.py`).
2. In Power BI: **Home > Refresh**.
3. Check `Last Refresh UTC` and `Latest Event UTC` on Page 1.

Save the report as `powerbi\CyberShield.pbix`. The `.gitignore` excludes `*.pbix`
by default, so it will not be committed unless you remove that line.

If you move the project folder, update `DataFolder` (**Transform data > Edit parameters**).

Scheduled refresh in the Power BI service would need a gateway for local files.
This project does not use one, so refresh is manual.

## 7. Expected values on the sample dataset

These were computed from `data/sample/` by running each measure's logic in
pandas, NOT in Power BI. Your numbers should match if you used the default seed.

| Measure (no slicers) | Expected |
|---|---|
| Total Events | 359 |
| Failed Logins | 116 |
| Successful Logins | 243 |
| Failure Rate | 32.3% |
| Synthetic Events / Local Lab Events | 343 / 16 |
| Unique Source IPs / Unique Usernames | 27 / 12 |
| Total Alerts | 6 |
| High / Medium / Low Severity Alerts | 2 / 1 / 3 |
| Alerts With Success After | 2 |
| Failed Attempts In Alert Windows | 47 |
| Average Attempts Per Alert | 7.83 |
| Largest Burst | 14 |
| Rejected Records | 0 |
| Evidence Events (no alert selected) | 49 |

Other checks:

* Alerts by source IP: `127.0.0.1` 2, `198.51.100.77` 1, `203.0.113.45` 2, `203.0.113.88` 1.
* Alerts by username: `admin_demo` 3, `alice_demo` 2, `bob_demo` 1.
* Select source type `local_lab` only: 16 events, 2 alerts.
* Date slicer 2026-10-01 to 2026-10-03: 129 events, 1 alert.
* Select IP `127.0.0.1` and user `alice_demo`: 7 events (5 failures, 2 successes), 1 alert.
* Select the alert for `alice_demo` from `127.0.0.1`: Evidence Failed Logins 5, Evidence Successful Logins 1.
* Select the alert for `bob_demo`: Evidence Failed Logins 8, Evidence Successful Logins 1.
* Select the largest alert (14): Evidence Failed Logins 14, Evidence Successful Logins 0.

The sample's local-lab events carry the day you generated the sample, so the
trend line on Page 1 shows a long quiet gap between the synthetic days and that day.
That is expected.

## 8. Common problems

| Problem | Fix |
|---|---|
| `DataSource.NotFound` or "file not found" | `DataFolder` is wrong or the file has not been generated. Check the path and run the pipeline. |
| "The process cannot access the file" | The CSV is open in Excel. Close it and refresh. |
| `Expression.Error: The column ... of the table wasn't found` | A CSV has different columns than expected: you may have an old file from before a schema change. Re-run the pipeline. |
| Dates show as text, or the trend is empty | The `ToUtc` step failed. Check that `timestamp_utc` in the CSV looks like `2026-10-01T10:00:00+00:00`. |
| Power BI warns about an ambiguous relationship | Delete the relationship between `Events` and `AlertEvidence`. Only the table in section 3.2 should exist. |
| A slicer does not filter some visuals | You used the same-named field from `Events` or `Alerts` instead of the `Dim*` table. Use the `Dim*` field. |
| Alert cards show "Multiple" | More than one alert is in view. Pick one alert in the alert slicer. |
| Numbers do not change after running the pipeline | Press **Home > Refresh**. The report is not live. |
| `Failed Logins` card shows blank | Use the measure with `+ 0` from section 4.1, and check that the date slicer is not excluding all data. |
| "Evidence" table is empty | Check the visual-level filter `Is Evidence Event is 1` and that `alert_evidence.csv` is loaded. |

## 9. Honest limits of this dashboard

* It reads CSV snapshots. It is **not** a live SOC console.
* Local-lab events all come from `127.0.0.1`, so per-IP separation on local data
  is not demonstrable (see the project README).
* Alerts come from a simple threshold rule. See the report for false-positive and
  false-negative discussion; the dashboard only shows what the rule found.
* Measure values were checked against the sample by reproducing their logic in
  pandas. Compare your own screen with section 7 and investigate any mismatch.