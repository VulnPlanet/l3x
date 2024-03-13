mod gpt_validator;
mod vulnerability_checks;
use crate::vulnerability_checks::VulnerabilityCheck;
mod report_generator;
use report_generator::{FinalReport, SecurityAnalysisSummary, VulnerabilityResult, SafePatternDetail};

use clap::{App, Arg};
use regex::Regex;
use std::{collections::HashMap, error::Error, fs};
use tokio::runtime::Runtime;
use walkdir::WalkDir;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("AI-driven Smart Contract Static Analyzer")
        .version("0.0.2")
        .author("YevhSec")
        .about("L3X detects vulnerabilities in Smart Contracts based on patterns and AI code analysis. Currently supports Solana based on Rust and Ethereum based on Solidity.")
        .arg(Arg::with_name("folder_path")
             .help("The path to the folder to scan")
             .required(true)
             .index(1))
        .arg(Arg::with_name("all_severities")
             .long("all-severities")
             .help("Validate findings of all severities, not just critical and high"))
        .get_matches();

    let folder_path = matches.value_of("folder_path").unwrap();
    let api_key = std::env::var("OPENAI_KEY").expect("OPENAI_KEY must be set");
    let validate_all_severities = matches.is_present("all_severities");

    let rt = Runtime::new()?;
    rt.block_on(async {
        let vulnerability_checks = vulnerability_checks::initialize_vulnerability_checks();
        let results_by_language = analyze_folder(folder_path, &api_key, &vulnerability_checks[..], validate_all_severities).await?;

        for (language, (files_list, vulnerabilities_details, safe_patterns_map)) in results_by_language {
            let safe_patterns_overview: Vec<SafePatternDetail> = safe_patterns_map.into_iter().map(|(_, detail)| detail).collect();

            let report = FinalReport {
                security_analysis_summary: SecurityAnalysisSummary {
                    checked_files: files_list.len(),
                    files_list,
                    security_issues_found: vulnerabilities_details.len(),
                },
                vulnerabilities_details,
                safe_patterns_overview,
            };

            let html_content = report_generator::generate_html_report(&report, &language);
            fs::write(format!("{}_L3X_SAST_Report.html", language), html_content).expect("Unable to write HTML report");
        }

        Ok(())
    })
}

async fn analyze_folder(
    folder_path: &str,
    api_key: &str,
    checks: &[VulnerabilityCheck],
    validate_all_severities: bool,
) -> Result<HashMap<String, (Vec<String>, Vec<VulnerabilityResult>, HashMap<String, SafePatternDetail>)>, Box<dyn Error>> {
    let mut results_by_language: HashMap<String, (Vec<String>, Vec<VulnerabilityResult>, HashMap<String, SafePatternDetail>)> = HashMap::new();

    for entry in WalkDir::new(folder_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let ext = e.path().extension().and_then(|e| e.to_str()).unwrap_or("");
            ext == "rs" || ext == "sol"
        }) {
        let path = entry.path();
        let language = match path.extension().and_then(|e| e.to_str()) {
            Some("rs") => "Rust",
            Some("sol") => "Solidity-Ethereum",
            _ => continue,
        };

        let file_content = fs::read_to_string(path)?;
        let (files_list, vulnerabilities_details, safe_patterns_overview) =
            results_by_language.entry(language.to_string()).or_insert_with(|| (Vec::new(), Vec::new(), HashMap::new()));

        files_list.push(path.to_string_lossy().to_string());

        // Group findings per file
        let mut findings_by_file = Vec::new();

        for (line_number, line) in file_content.lines().enumerate() {
            for check in checks.iter().filter(|c| c.language == language) {
                let pattern_regex = Regex::new(&check.pattern)?;
                let safe_pattern_regex = check.safe_pattern.as_ref().and_then(|sp| Regex::new(sp).ok());

                if pattern_regex.is_match(line) {
                    findings_by_file.push((line_number + 1, check.id.clone(), check.severity.clone(), check.suggested_fix.clone()));
                }

                if let Some(safe_regex) = &safe_pattern_regex {
                    if safe_regex.is_match(line) {
                        let entry = safe_patterns_overview.entry(check.id.clone()).or_insert_with(|| SafePatternDetail {
                            pattern_id: check.id.clone(),
                            title: check.title.clone(),
                            safe_pattern: check.safe_pattern.clone().unwrap_or_default(),
                            occurrences: 0,
                            files: vec![],
                        });

                        entry.occurrences += 1;
                        if !entry.files.contains(&path.to_string_lossy().to_string()) {
                            entry.files.push(path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }

        if !findings_by_file.is_empty() {
            let (status, _) = gpt_validator::validate_vulnerabilities_with_gpt(api_key, &findings_by_file, &file_content, language, validate_all_severities).await?;

            for (_line_number, vulnerability_id, severity, suggested_fix) in findings_by_file {
                vulnerabilities_details.push(VulnerabilityResult {
                    vulnerability_id: vulnerability_id.clone(),
                    file: path.to_string_lossy().to_string(),
                    title: checks.iter().find(|c| c.id == vulnerability_id).unwrap().title.clone(),
                    severity,
                    status: status.clone(),
                    description: checks.iter().find(|c| c.id == vulnerability_id).unwrap().description.clone(),
                    fix: suggested_fix,
                    persistence_of_safe_pattern: "No".to_string(),
                    safe_pattern: None,
                });
            }
        }
    }

    Ok(results_by_language)
}
