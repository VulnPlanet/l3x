mod gpt_validator;

use clap::{App, Arg};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error, fs};
use tokio::runtime::Runtime;
use walkdir::WalkDir;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VulnerabilityCheck {
    id: String,
    title: String,
    severity: String,
    pattern: String,
    safe_pattern: Option<String>,
    description: String,
    suggested_fix: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct VulnerabilityResult {
    vulnerability_id: String,
    file: String,
    title: String,
    severity: String,
    status: String,
    description: String,
    fix: String,
    persistence_of_safe_pattern: String,
    safe_pattern: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct FinalReport {
    security_analysis_summary: SecurityAnalysisSummary,
    vulnerabilities_details: Vec<VulnerabilityResult>,
    safe_patterns_overview: Vec<SafePatternDetail>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SecurityAnalysisSummary {
    checked_files: usize,
    files_list: Vec<String>,
    security_issues_found: usize,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SafePatternDetail {
    pattern_id: String,
    title: String,
    safe_pattern: String,
    occurrences: usize,
    files: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Rust Vulnerability Scanner")
        .version("1.0.0")
        .author("YevhSec")
        .about("Scans Rust projects for common vulnerabilities and reports on safe practices.")
        .arg(Arg::with_name("folder_path")
             .help("The path to the folder to scan")
             .required(true)
             .index(1))
        .get_matches();

    let folder_path = matches.value_of("folder_path").unwrap();
    let api_key = std::env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY must be set");

    let rt = Runtime::new()?;
    rt.block_on(async {
        let vulnerability_checks = initialize_vulnerability_checks();
        let (files_list, vulnerabilities_details, safe_patterns_overview) = analyze_folder(folder_path, &api_key, &vulnerability_checks).await.unwrap();

        let report = FinalReport {
            security_analysis_summary: SecurityAnalysisSummary {
                checked_files: files_list.len(),
                files_list: files_list,
                security_issues_found: vulnerabilities_details.len(),
            },
            vulnerabilities_details: vulnerabilities_details,
            safe_patterns_overview: safe_patterns_overview,
        };

        let html_content = generate_html_report(&report);
        
        fs::write("L3X_SAST_Report.html", html_content).expect("Unable to write HTML report");

        Ok(())
    })
}

fn generate_html_report(report: &FinalReport) -> String {
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
        <p>Technology: Solana<br>Languange: Rust</p>
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
        vulnerabilities_html = vulnerabilities_html,
        safe_patterns_html = safe_patterns_html,
        severity_count_json = severity_count_json,
        total_valid = total_valid,
        total_invalid = total_invalid
    )
}



async fn analyze_folder(
    folder_path: &str,
    api_key: &str,
    checks: &[VulnerabilityCheck],
) -> Result<(Vec<String>, Vec<VulnerabilityResult>, Vec<SafePatternDetail>), Box<dyn Error>> {
    let mut files_list = Vec::new();
    let mut vulnerabilities_details = Vec::new();
    let mut safe_patterns_map: HashMap<String, SafePatternDetail> = HashMap::new();

    for entry in WalkDir::new(folder_path).into_iter().filter_map(|e| e.ok()).filter(|e| e.path().extension().map_or(false, |ext| ext == "rs")) {
        let path = entry.path();
        let file_content = fs::read_to_string(path)?;
        files_list.push(path.to_string_lossy().to_string());

        for check in checks {
            let pattern_regex = Regex::new(&check.pattern)?;
            let safe_pattern_regex = check.safe_pattern.as_ref().and_then(|sp| Regex::new(sp).ok());

            find_vulnerabilities_and_safe_patterns(
                &path.to_string_lossy(),
                &file_content,
                check,
                &pattern_regex,
                &safe_pattern_regex,
                api_key,
                &mut vulnerabilities_details,
                &mut safe_patterns_map,
            ).await?;
        }
    }

    let safe_patterns_overview = safe_patterns_map.into_values().collect();

    Ok((files_list, vulnerabilities_details, safe_patterns_overview))
}

async fn find_vulnerabilities_and_safe_patterns(
    path: &str,
    content: &str,
    check: &VulnerabilityCheck,
    pattern_regex: &Regex,
    safe_pattern_regex: &Option<Regex>,
    api_key: &str,
    vulnerabilities: &mut Vec<VulnerabilityResult>,
    safe_patterns: &mut HashMap<String, SafePatternDetail>,
) -> Result<(), Box<dyn Error>> {
    if let Some(captures) = pattern_regex.captures(content) {
        let line_of_code = captures.get(0).map_or("", |m| m.as_str());
        let line_number = content[..captures.get(0).unwrap().start()].matches('\n').count() + 1;
        let (status, fix) = gpt_validator::validate_vulnerability_with_gpt(api_key, &check.title, &check.severity, line_number, line_of_code, content).await?;

        vulnerabilities.push(VulnerabilityResult {
            vulnerability_id: check.id.clone(),
            file: path.to_string(),
            title: check.title.clone(),
            severity: check.severity.clone(),
            status: status,
            description: check.description.clone(),
            fix: fix,
            persistence_of_safe_pattern: "No".to_string(),
            safe_pattern: check.safe_pattern.clone(),
        });
    }

    if let Some(regex) = safe_pattern_regex {
        for _mat in regex.find_iter(content) {
            let entry = safe_patterns.entry(check.id.clone()).or_insert_with(|| SafePatternDetail {
                pattern_id: check.id.clone(),
                title: check.title.clone(),
                safe_pattern: check.safe_pattern.clone().unwrap_or_default(),
                occurrences: 0,
                files: vec![],
            });

            entry.occurrences += 1;
            if !entry.files.contains(&path.to_string()) {
                entry.files.push(path.to_string());
            }
        }
    }

    Ok(())
}

fn initialize_vulnerability_checks() -> Vec<VulnerabilityCheck> {
    vec![
        VulnerabilityCheck {
            id: "VULN001".to_string(),
            title: "Integer Overflow or Underflow".to_string(),
            severity: "High".to_string(),
            pattern: r"let\s+\w+\s*=\s*\w+\.\w+\s*[+\-*\/]\s*\w+;".to_string(),
            safe_pattern: Some(r"\.checked_add\(|\.checked_sub\(|\.checked_mul\(|\.checked_div\(".to_string()),
            description: "Performing arithmetic operation without checking for overflow or underflow.".to_string(),
            suggested_fix: "Use `checked_add`, `checked_sub`, `checked_mul`, or `checked_div` to safely perform arithmetic operations.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN002".to_string(),
            title: "Loss of Precision".to_string(),
            severity: "High".to_string(),
            pattern: r"\.try_round_u64\(\s*\)".to_string(),
            safe_pattern: Some(r"\.try_floor_u64\(\s*\)".to_string()),
            description: "The use of try_round_u64() for rounding up may lead to loss of precision.".to_string(),
            suggested_fix: "Use try_floor_u64() to prevent potential loss of precision.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN003".to_string(),
            title: "Inaccurate Calculation Results".to_string(),
            severity: "High".to_string(),
            pattern: r"\.saturating_(add|sub|mul)\(".to_string(),
            safe_pattern: Some(r"\.checked_(add|sub|mul|div)\(".to_string()),
            description: "Reliance on saturating arithmetic operations without considering precision loss.".to_string(),
            suggested_fix: "Consider using `checked_add`, `checked_sub`, `checked_mul`, or `checked_div` to handle arithmetic operations explicitly and avoid precision loss.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN004".to_string(),
            title: "Panic due to Division by Zero".to_string(),
            severity: "High".to_string(),
            pattern: r"\b\d+\s*/\s*0\b".to_string(),
            safe_pattern: None,
            description: "Division by zero causing the program to panic and terminate unexpectedly.".to_string(),
            suggested_fix: "Ensure divisor is not zero before performing division, or use checked division methods.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN006".to_string(),
            title: "Error Not Handled".to_string(),
            severity: "High".to_string(),
            pattern: r"&spl_token::instruction::transfer\s*\(".to_string(),
            safe_pattern: Some(r"&spl_token::instruction::transfer\s*\(.*\)?;".to_string()),
            description: "Function calls that might return `Err` are not checked for errors.".to_string(),
            suggested_fix: "Ensure that results are checked for errors. Use `?` at the end of the line to propagate errors.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN007".to_string(),
            title: "Missing Check for the Permission of Caller".to_string(),
            severity: "Low".to_string(),
            pattern: r"fn\s+init_market\s*\(\s*accounts\s*:\s*&\[AccountInfo\]\s*\)\s*->\s*ProgramResult\s*\{".to_string(),
            safe_pattern: Some(r"require_is_authorized_signer\(".to_string()), 
            description: "Missing verification of caller permissions before sensitive operations.".to_string(),
            suggested_fix: "Implement and invoke a permission check function to verify the caller's authority.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN008".to_string(),
            title: "Account Signer Check".to_string(),
            severity: "High".to_string(),
            pattern: r"next_account_info\s*\(".to_string(),
            safe_pattern: Some(r"if\s+!\w+\.is_signer".to_string()),
            description: "Ensure the expected signer account has actually signed to prevent unauthorized account modifications.".to_string(),
            suggested_fix: "Verify `is_signer` is true for transactions requiring signatures.".to_string(),
        },
        
        VulnerabilityCheck {
            id: "VULN009".to_string(),
            title: "Account Writable Check".to_string(),
            severity: "High".to_string(),
            pattern: r"next_account_info\s*\(".to_string(),
            safe_pattern: Some(r"if\s+!\w+\.is_writable".to_string()),
            description: "Ensure state accounts are checked as writable to prevent unauthorized modifications.".to_string(),
            suggested_fix: "Verify `is_writable` is true for accounts that should be modified.".to_string(),
        },
        
        VulnerabilityCheck {
            id: "VULN010".to_string(),
            title: "Account Owner or Program ID Check".to_string(),
            severity: "High".to_string(),
            pattern: r"next_account_info\s*\(".to_string(),
            safe_pattern: Some(r"if\s+\w+\.owner\s*!=".to_string()),
            description: "Verify the owner of state accounts to prevent fake data injection by malicious programs.".to_string(),
            suggested_fix: "Check the account's owner matches the expected program ID.".to_string(),
        },
        
        VulnerabilityCheck {
            id: "VULN011".to_string(),
            title: "Account Initialized Check".to_string(),
            severity: "High".to_string(),
            pattern: r"try_from_slice\s*\(".to_string(),
            safe_pattern: Some(r"if\s+\w+\.is_initialized".to_string()),
            description: "Prevent re-initialization of already initialized accounts.".to_string(),
            suggested_fix: "Ensure account's `is_initialized` flag is checked before initializing.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN017".to_string(),
            title: "Signer Authorization - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"pub\s+fn\s+\w+\s*\(ctx:\s*Context<\w+>\)\s*->\s*ProgramResult\s*\{".to_string(),
            safe_pattern: Some(r"if\s+!\w+\.is_signer\s*\{".to_string()),
            description: "Signer check is missing, which could lead to unauthorized execution.".to_string(),
            suggested_fix: "Add a check to verify if the caller is a signer.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN018".to_string(),
            title: "Account Data Matching - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"SplTokenAccount::unpack\(&ctx.accounts.\w+.data.borrow\(\)\)".to_string(),
            safe_pattern: Some(r"if\s+ctx\.accounts\.\w+\.key\s*!=\s*&\w+\.owner\s*\{".to_string()),
            description: "Missing verification of token ownership or mint authority in SPL Token accounts.".to_string(),
            suggested_fix: "Verify token ownership matches the expected authority before proceeding.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN019".to_string(),
            title: "Owner Checks - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"SplTokenAccount::unpack\(&ctx.accounts.\w+.data.borrow\(\)\)".to_string(),
            safe_pattern: Some(r"if\s+ctx.accounts.\w+.owner\s*!=\s*&spl_token::ID\s*\{".to_string()),
            description: "Missing checks on the owner field in the metadata of an Account or on the Account itself.".to_string(),
            suggested_fix: "Ensure the owner of the account is verified against the expected program ID.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN020".to_string(),
            title: "Type Cosplay - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"User::try_from_slice\(&ctx.accounts.\w+.data.borrow\(\)\)".to_string(),
            safe_pattern: Some(r"if\s+\w+.discriminant\s*!=\s*AccountDiscriminant::\w+\s*\{".to_string()),
            description: "Risks of different accounts impersonating each other by sharing identical data structures.".to_string(),
            suggested_fix: "Add discriminant checks to differentiate account types securely.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN021".to_string(),
            title: "Check Initialize - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"User::try_from_slice\(&ctx.accounts.\w+.data.borrow\(\)\)".to_string(),
            safe_pattern: Some(r"if\s+\w+.discriminator\s*==\s*true\s*\{".to_string()),
            description: "Data should only be initialized once; missing checks can lead to reinitialization.".to_string(),
            suggested_fix: "Use a flag to ensure data is initialized only once.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN022".to_string(),
            title: "Arbitrary CPI - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"solana_program::program::invoke\(".to_string(),
            safe_pattern: Some(r"if &spl_token::ID != ctx.accounts.token_program.key \{".to_string()),
            description: "Unverified target program id in CPI can lead to arbitrary code execution.".to_string(),
            suggested_fix: "Ensure the target program id is verified against expected program id.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN023".to_string(),
            title: "Duplicate Mutable Accounts - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"let\s+user_a\s+=\s+&mut\s+ctx.accounts.user_a;.*let\s+user_b\s+=\s+&mut\s+ctx.accounts.user_b;".to_string(),
            safe_pattern: Some(r"if ctx.accounts.user_a.key\(\) == ctx.accounts.user_b.key\(\) \{".to_string()),
            description: "Passing the same mutable account multiple times may result in unintended data overwriting.".to_string(),
            suggested_fix: "Add checks to ensure that mutable accounts passed are distinct.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN024".to_string(),
            title: "Bump Seed Canonicalization  - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"Pubkey::create_program_address\(&\[".to_string(),
            safe_pattern: Some(r"let \(address, expected_bump\) = Pubkey::find_program_address\(&\[".to_string()),
            description: "Improper validation of bump seeds can lead to security vulnerabilities.".to_string(),
            suggested_fix: "Use `find_program_address` for bump seed canonicalization and validate against expected seeds.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN025".to_string(),
            title: "PDA Sharing  - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"token::transfer\(ctx.accounts.transfer_ctx\(\).with_signer\(&\[\w+\]\),".to_string(),
            safe_pattern: Some(r"let seeds = &\[\w+.withdraw_destination.as_ref\(\), &\[\w+.bump\]\];".to_string()),
            description: "Sharing PDA across multiple roles without proper permission separation may lead to unauthorized access.".to_string(),
            suggested_fix: "Ensure PDAs used across roles have distinct seeds and permissions.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN026".to_string(),
            title: "Closing Accounts  - Anchor".to_string(),
            severity: "High".to_string(),
            pattern: r"\*\*ctx.accounts.account.to_account_info\(\).lamports.borrow_mut\(\) = 0;".to_string(),
            safe_pattern: Some(r"let mut data = account.try_borrow_mut_data\(\)?;.*CLOSED_ACCOUNT_DISCRIMINATOR".to_string()),
            description: "Improper closing of accounts may leave them vulnerable to misuse.".to_string(),
            suggested_fix: "Ensure accounts are properly closed by transferring lamports and marking with a discriminator.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN027".to_string(),
            title: "Sysvar System Account Not Checked".to_string(),
            severity: "High".to_string(),
            pattern: r"solana_program::sysvar::instructions::load_current_index\(\s*&accs\.\w+\.try_borrow_mut_data\(\)\?\s*\)".to_string(),
            safe_pattern: Some(r"if \*accs\.\w+\.key != solana_program::sysvar::instructions::id\(\) \{".to_string()),
            description: "Sysvar system account is accessed without verifying its legitimacy, exposing the contract to potential manipulation or attacks.".to_string(),
            suggested_fix: "Before deserializing information from a sysvar account, verify that the incoming address matches the expected sysvar ID.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN028".to_string(),
            title: "PDA Account Misuse Without Proper Verification".to_string(),
            severity: "High".to_string(),
            pattern: r"CpiContext::new\(\s*self.token_program.clone\(\),\s*Transfer\s*\{.*?authority: self.market_authority.clone\(\),.*?\}\s*\)".to_string(),
            safe_pattern: Some(r"CpiContext::new\(.*Burn\s*\{.*?authority: self.depositor.clone\(\),.*?\}\s*\)".to_string()),
            description: "The PDA account is utilized without validating the caller's and beneficiary's accounts, allowing unauthorized actions such as burning other users' Tokens and transferring proceeds to an attacker's account.".to_string(),
            suggested_fix: "Implement checks to verify the depositor's signature and ensure the deposit_account cannot be forged by validating the derived address generated by seeds from reserve.key and depositor.key.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN029".to_string(),
            title: "Unchecked Account Deserialization".to_string(),
            severity: "High".to_string(),
            pattern: r"try_from_slice\(&ctx.accounts.\w+.data.borrow\(\)\?\)".to_string(),
            safe_pattern: Some(r"if ctx.accounts.\w+.owner == &expected_program_id { ... }".to_string()),
            description: "Failing to check if an account is of the expected type before deserializing can lead to incorrect assumptions about state.".to_string(),
            suggested_fix: "Ensure accounts are of the expected type before deserialization.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN030".to_string(),
            title: "Log Injection".to_string(),
            severity: "Medium".to_string(),
            pattern: r"msg!\(.*?\)".to_string(),
            safe_pattern: None,
            description: "Injection vulnerabilities in program logs can lead to misleading or harmful information being logged.".to_string(),
            suggested_fix: "Sanitize all inputs that are logged to prevent log injection attacks.".to_string(),
        },
        VulnerabilityCheck {
            id: "VULN031".to_string(),
            title: "CPI to Unauthorized Programs".to_string(),
            severity: "High".to_string(),
            pattern: r"invoke\(\[.*?\], &[.*?]\)".to_string(),
            safe_pattern: Some(r"if &authorized_programs.contains(&program_id) { ... }".to_string()),
            description: "Invoking unauthorized or risky external programs can expose the contract to vulnerabilities present in those programs.".to_string(),
            suggested_fix: "Whitelist external programs that can be invoked, and perform thorough security reviews on them.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST001".to_string(),
            title: "Misuse of Unsafe Code".to_string(),
            severity: "High".to_string(),
            pattern: r"unsafe\s*\{".to_string(),
            safe_pattern: None,
            description: "Unsafe blocks may lead to undefined behavior and memory safety violations if not used carefully. Ensure justification and proper auditing.".to_string(),
            suggested_fix: "Minimize the use of `unsafe` by leveraging safe Rust abstractions and validate all `unsafe` blocks for safety guarantees.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST002".to_string(),
            title: "Improper Error Handling".to_string(),
            severity: "Medium".to_string(),
            pattern: r"\.unwrap\(\)|\.expect\(".to_string(),
            safe_pattern: None,
            description: "Overuse of `unwrap()` or `expect()` can lead to panics. Prefer using error handling mechanisms like `match` or `if let`.".to_string(),
            suggested_fix: "Replace `unwrap()` and `expect()` with proper error handling to prevent unexpected panics in production code.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST003".to_string(),
            title: "Overuse of Panics for Control Flow".to_string(),
            severity: "Medium".to_string(),
            pattern: r"panic!\(".to_string(),
            safe_pattern: None,
            description: "Using panics for control flow makes code hard to follow and can lead to unexpected termination.".to_string(),
            suggested_fix: "Use Result types for error handling and reserve panics for unrecoverable errors only.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST004".to_string(),
            title: "Concurrency Issues and Data Races".to_string(),
            severity: "High".to_string(),
            pattern: r"std::thread|std::sync".to_string(),
            safe_pattern: None,
            description: "Improper handling of threads and synchronization can lead to data races, deadlocks, and other concurrency issues.".to_string(),
            suggested_fix: "Use Rust's concurrency primitives correctly, prefer `std::sync` module's types like Mutex, RwLock, and leverage the `rayon` crate for data parallelism.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST005".to_string(),
            title: "Potential Memory Leaks".to_string(),
            severity: "Low".to_string(),
            pattern: r"Rc<|Arc<|Box<".to_string(),
            safe_pattern: None,
            description: "Cyclic references or improper use of smart pointers can lead to memory leaks.".to_string(),
            suggested_fix: "Use `Weak` pointers to break cycles and audit memory usage regularly.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST006".to_string(),
            title: "Potential DoS Vulnerabilities".to_string(),
            severity: "High".to_string(),
            pattern: r"\.clone\(|Vec::with_capacity\(|String::with_capacity\(".to_string(),
            safe_pattern: None,
            description: "Allocations based on untrusted input sizes can lead to DoS via memory exhaustion.".to_string(),
            suggested_fix: "Validate input sizes before allocations and use bounded collections. Consider rate-limiting or other mitigation strategies.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST007".to_string(),
            title: "Missing Boundary Checks".to_string(),
            severity: "Medium".to_string(),
            pattern: r"\[\w+\]".to_string(),
            safe_pattern: Some(r"\.get\(\w+\)".to_string()),
            description: "Accessing arrays or vectors without boundary checks can lead to panics or buffer overflows.".to_string(),
            suggested_fix: "Use `.get()` or `.get_mut()` for safe access with bounds checking, and handle the Option result appropriately.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST008".to_string(),
            title: "Unnecessary Cloning of Large Data Structures".to_string(),
            severity: "Low".to_string(),
            pattern: r"\.clone\(".to_string(),
            safe_pattern: None,
            description: "Cloning large data structures can lead to performance issues due to excessive memory use.".to_string(),
            suggested_fix: "Prefer borrowing or using reference-counted types like `Rc` or `Arc` to share data without deep copying.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST009".to_string(),
            title: "Blocking I/O in Asynchronous Code".to_string(),
            severity: "Medium".to_string(),
            pattern: r"std::fs|std::net".to_string(),
            safe_pattern: Some(r"tokio::fs|tokio::net".to_string()),
            description: "Performing blocking I/O operations in async contexts can lead to thread starvation and reduced scalability.".to_string(),
            suggested_fix: "Use asynchronous equivalents for file and network operations within async functions.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST010".to_string(),
            title: "Misuse of Arc<Mutex<T>>".to_string(),
            severity: "Medium".to_string(),
            pattern: r"Arc<Mutex<.*?>>".to_string(),
            safe_pattern: None,
            description: "Incorrect use of Arc<Mutex<T>> can lead to deadlocks or inefficient locking mechanisms.".to_string(),
            suggested_fix: "Ensure that locks are held for the minimum duration necessary, and consider other synchronization primitives like RwLock if applicable.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST011".to_string(),
            title: "Improper Implementation of Drop Trait".to_string(),
            severity: "Medium".to_string(),
            pattern: r"impl\s+Drop\s+for\s+.*?\s*\{".to_string(),
            safe_pattern: None,
            description: "Incorrect custom implementations of the Drop trait can lead to resource leaks or panic safety issues.".to_string(),
            suggested_fix: "Implement the Drop trait carefully, ensuring that errors are handled gracefully and resources are properly released.".to_string(),
        },
        VulnerabilityCheck {
            id: "RUST012".to_string(),
            title: "Usage of mem::uninitialized and mem::zeroed".to_string(),
            severity: "High".to_string(),
            pattern: r"mem::uninitialized\(\)|mem::zeroed\(\)".to_string(),
            safe_pattern: None,
            description: "Using mem::uninitialized or mem::zeroed can lead to undefined behavior if the type has any non-zero or complex initialization requirements.".to_string(),
            suggested_fix: "Prefer using safe initialization patterns and avoid these functions for types with non-trivial initialization requirements.".to_string(),
        },
    ]
}
