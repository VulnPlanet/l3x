use std::collections::HashMap;
use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct FinalReport {
    pub security_analysis_summary: SecurityAnalysisSummary,
    pub vulnerabilities_details: Vec<VulnerabilityResult>,
    pub safe_patterns_overview: Vec<SafePatternDetail>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecurityAnalysisSummary {
    pub checked_files: usize,
    pub files_list: Vec<String>,
    pub security_issues_found: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityResult {
    pub vulnerability_id: String,
    pub file: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub description: String,
    pub fix: String,
    pub persistence_of_safe_pattern: String,
    pub safe_pattern: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SafePatternDetail {
    pub pattern_id: String,
    pub title: String,
    pub safe_pattern: String,
    pub occurrences: usize,
    pub files: Vec<String>,
}

pub fn generate_html_report(report: &FinalReport, language: &str) -> String {
    let severity_order = |severity: &str| match severity {
        "Critical" => 1,
        "High" => 2,
        "Medium" => 3,
        "Low" => 4,
        _ => 5,
    };

    let (mut valid_vulnerabilities, mut invalid_vulnerabilities): (Vec<_>, Vec<_>) = report.vulnerabilities_details
        .iter()
        .partition(|v| v.status == "Valid");

    valid_vulnerabilities.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
    invalid_vulnerabilities.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));

    let sorted_vulnerabilities = valid_vulnerabilities.into_iter().chain(invalid_vulnerabilities.into_iter());

    let vulnerabilities_html = sorted_vulnerabilities.map(|v| {
        let status_icon = if v.status == "Valid" {
            "🟢 GPT 3.5"
        } else {
            "🔴 GPT 3.5"
        };

        format!(
            "<tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>",
            v.vulnerability_id, v.title, status_icon, v.severity, v.file, v.description, v.fix
        )
    }).collect::<String>();

    let safe_patterns_html = report.safe_patterns_overview.iter().map(|p| {
        format!(
            "<tr>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>",
            p.pattern_id, p.title, p.safe_pattern
        )
    }).collect::<String>();

    let mut severity_count = HashMap::new();
    let mut total_valid = 0;
    let mut total_invalid = 0;

    for v in &report.vulnerabilities_details {
        if v.status == "Valid" {
            *severity_count.entry(&v.severity).or_insert(0) += 1;
            total_valid += 1;
        } else {
            total_invalid += 1;
        }
    }

    let severity_count_json = serde_json::to_string(&severity_count).unwrap();

    format!(
        "<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Vulnerability Report</title>
    <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
    <style>
    body {{
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        margin: 0;
        padding: 20px;
        background-color: #f0f2f5;
    }}
    h1, h2 {{
        color: #333;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
    }}
    th, td {{
        padding: 8px;
        text-align: left;
        border-bottom: 1px solid #ddd;
    }}
    tr:hover {{background-color: #f5f5f5;}}
    th {{
        background-color: #04AA6D;
        color: white;
    }}
    .chart-container {{
        width: 400px;
        display: inline-block;
        margin: 20px;
    }}
    .charts-wrapper {{
        text-align: center;
    }}
</style>
</head>
<body>
    <header>
        <h1>L3X - Static Application Security Testing (SAST) Report</h1>
        <p>Technology: {language}</p>
        <p>Check more on: <a href='https://vulnplanet.com/'>VulnPlanet</a><br>Contribute: <a href='https://github.com/VulnPlanet/l3x'>GitHub</a></p>
    </header>
    <section>
    <h2>Summary</h2>
    <div class='chart-container'>
        <h3>By Severity</h3>
        <canvas id='severityChart'></canvas>
    </div>
    <div class='chart-container'>
        <h3>False Positive Rate</h3>
        <canvas id='falsePositiveChart'></canvas>
    </div>
</section>      
    <section>
        <h2>Vulnerabilities</h2>
        <p>🟢 GPT 3.5 - Valid or Not possible to determine</p>
        <p>🔴 GPT 3.5 - False Positive</p>
        <table>
            <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Status</th>
                <th>Severity</th>
                <th>File</th>
                <th>Description</th>
                <th>Details</th>
            </tr>
            {vulnerabilities_html}
        </table>
    </section>
    <section>
        <h2>Safe Patterns Overview</h2>
        <table>
            <tr>
                <th>Pattern ID</th>
                <th>Title</th>
                <th>Safe Pattern</th>
            </tr>
            {safe_patterns_html}
        </table>
    </section>
    <script>
        var severityData = JSON.parse('{severity_count_json}');
        var totalValid = {total_valid};
        var totalInvalid = {total_invalid};

        var severityCtx = document.getElementById('severityChart').getContext('2d');
        var falsePositiveCtx = document.getElementById('falsePositiveChart').getContext('2d');
        
        new Chart(severityCtx, {{
            type: 'bar',
            data: {{
                labels: Object.keys(severityData),
                datasets: [{{
                    label: 'Count',
                    data: Object.values(severityData),
                    backgroundColor: 'rgba(54, 162, 235, 0.5)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }}]
            }},
            options: {{
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});

        new Chart(falsePositiveCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Valid', 'False Positive'],
                datasets: [{{
                    label: 'Rate',
                    data: [totalValid, totalInvalid],
                    backgroundColor: [
                        'rgba(75, 192, 192, 0.5)',
                        'rgba(255, 99, 132, 0.5)'
                    ],
                    borderColor: [
                        'rgba(75, 192, 192, 1)',
                        'rgba(255, 99, 132, 1)'
                    ],
                    borderWidth: 1
                }}]
            }},
        }});
    </script>
</body>
</html>",
        language = language,
        vulnerabilities_html = vulnerabilities_html,
        safe_patterns_html = safe_patterns_html,
        severity_count_json = severity_count_json,
        total_valid = total_valid,
        total_invalid = total_invalid
    )
}
