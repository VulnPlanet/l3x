use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: MessageContent,
}

#[derive(Deserialize)]
struct MessageContent {
    content: String,
}

pub async fn validate_vulnerability_with_gpt(
    api_key: &str,
    title: &str,
    severity: &str,
    line_number: usize,
    line_of_code: &str,
    file_content: &str,
) -> Result<(String, String), Box<dyn Error>> {
    let client = Client::new();
    let prompt = format!(
        "A Static Application Security Testing (SAST) tool detects a potential vulnerability titled '{title}' with severity '{severity}' at line number {line_number} in the following Rust code file. The line of code flagged is:\n\n{line_of_code}\n\nThe full code of the file is provided below for context:\n\n{file_content}\n\nBased on the information provided and the full code context, please validate whether this vulnerability is valid or a false positive. Additionally, if the vulnerability is valid, suggest a possible fix.",
        title = title,
        severity = severity,
        line_number = line_number,
        line_of_code = line_of_code,
        file_content = file_content
    );

    let chat_request = ChatRequest {
        model: "gpt-3.5-turbo".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: prompt,
        }],
    };

    let response = client.post("https://api.openai.com/v1/chat/completions")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&chat_request)
        .send()
        .await?;

    if response.status().is_success() {
        let chat_response = response.json::<ChatResponse>().await?;
        let text = chat_response.choices.get(0).map_or_else(|| "", |choice| &choice.message.content);

        let status = if text.contains("not a vulnerability")
            || text.contains("is not a valid vulnerability")
            || text.to_lowercase().contains("appears to be a false positive")
            || text.to_lowercase().contains("is no vulnerability present")
            || text.to_lowercase().contains("is a false positive")
            || text.to_lowercase().contains("likely a false positive")
            || text.to_lowercase().contains("may be a false positive")
            || text.to_lowercase().contains("seems to be a false positive")
            || text.to_lowercase().contains("most likely a false positive")
            || text.to_lowercase().contains("does not contain a vulnerability")
            || text.to_lowercase().contains("not appear to have a potential vulnerability")
            || text.to_lowercase().contains("does not seem to have any obvious vulnerability")
            || text.to_lowercase().contains("does not introduce a vulnerability")
            || text.to_lowercase().contains("not suggest any security issues")
            || text.to_lowercase().contains("does not appear to be vulnerable")
            || text.to_lowercase().contains("does not appear to have any clear vulnerability")
            || text.to_lowercase().contains("does not appear to have any potential vulnerability")
            || text.to_lowercase().contains("is not valid in this case")
            || text.to_lowercase().contains("does not appear to be valid")
            || text.to_lowercase().contains("does not appear to contain any potential vulnerability")
            || text.is_empty()
        {
            "False positive"
        } else {
            "Valid"
        };

        Ok((status.to_string(), text.to_string()))
    } else {
        Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to get a valid response from OpenAI")))
    }
}
