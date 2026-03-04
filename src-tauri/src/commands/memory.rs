/// 记忆文件管理命令
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use crate::utils::openclaw_command_async;

/// 检查路径是否包含不安全字符（目录遍历、绝对路径等）
fn is_unsafe_path(path: &str) -> bool {
    path.contains("..")
        || path.contains('\0')
        || path.starts_with('/')
        || path.starts_with('\\')
        || (path.len() >= 2 && path.as_bytes()[1] == b':') // Windows 绝对路径 C:\
}

/// 根据 agent_id 获取 workspace 路径（异步版本）
/// 调用 openclaw agents list --json 解析
async fn agent_workspace(agent_id: &str) -> Result<PathBuf, String> {
    let output = openclaw_command_async()
        .args(["agents", "list", "--json"])
        .output()
        .await
        .map_err(|e| format!("执行 openclaw 失败: {e}"))?;

    if !output.status.success() {
        return Err("获取 Agent 列表失败".into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let agents: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("解析 JSON 失败: {e}"))?;

    if let Some(arr) = agents.as_array() {
        for a in arr {
            if a.get("id").and_then(|v| v.as_str()) == Some(agent_id) {
                if let Some(ws) = a.get("workspace").and_then(|v| v.as_str()) {
                    return Ok(PathBuf::from(ws));
                }
            }
        }
    }

    Err(format!("Agent「{agent_id}」不存在或无 workspace"))
}

async fn memory_dir_for_agent(agent_id: &str, category: &str) -> Result<PathBuf, String> {
    let ws = agent_workspace(agent_id).await?;
    Ok(match category {
        "memory" => ws.join("memory"),
        "archive" => {
            // 归档目录在 agent workspace 同级的 workspace-memory
            // 对 main: ~/.openclaw/workspace-memory
            // 对其他: ~/.openclaw/agents/{id}/workspace-memory
            if let Some(parent) = ws.parent() {
                parent.join("workspace-memory")
            } else {
                ws.join("memory-archive")
            }
        }
        "core" => ws.clone(),
        _ => ws.join("memory"),
    })
}

#[tauri::command]
pub async fn list_memory_files(category: String, agent_id: Option<String>) -> Result<Vec<String>, String> {
    let aid = agent_id.as_deref().unwrap_or("main");
    let dir = memory_dir_for_agent(aid, &category).await?;
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut files = Vec::new();
    collect_files(&dir, &dir, &mut files, &category)?;
    files.sort();
    Ok(files)
}

fn collect_files(
    base: &PathBuf,
    dir: &PathBuf,
    files: &mut Vec<String>,
    category: &str,
) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|e| format!("读取目录失败: {e}"))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // core 类别只读根目录的 .md 文件
            if category != "core" {
                collect_files(base, &path, files, category)?;
            }
        } else {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "md" | "txt" | "json" | "jsonl") {
                let rel = path.strip_prefix(base)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| path.to_string_lossy().to_string());
                files.push(rel);
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn read_memory_file(path: String, agent_id: Option<String>) -> Result<String, String> {
    if is_unsafe_path(&path) {
        return Err("非法路径".to_string());
    }

    let aid = agent_id.as_deref().unwrap_or("main");
    let candidates = [
        memory_dir_for_agent(aid, "memory").await,
        memory_dir_for_agent(aid, "archive").await,
        memory_dir_for_agent(aid, "core").await,
    ];

    for c in &candidates {
        if let Ok(dir) = c {
            let full = dir.join(&path);
            if full.exists() {
                return fs::read_to_string(&full)
                    .map_err(|e| format!("读取失败: {e}"));
            }
        }
    }

    Err(format!("文件不存在: {path}"))
}

#[tauri::command]
pub async fn write_memory_file(path: String, content: String, category: Option<String>, agent_id: Option<String>) -> Result<(), String> {
    if is_unsafe_path(&path) {
        return Err("非法路径".to_string());
    }

    let aid = agent_id.as_deref().unwrap_or("main");
    let cat = category.unwrap_or_else(|| "memory".to_string());
    let base = memory_dir_for_agent(aid, &cat).await?;

    let full_path = base.join(&path);
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    fs::write(&full_path, &content).map_err(|e| format!("写入失败: {e}"))
}

#[tauri::command]
pub async fn delete_memory_file(path: String, agent_id: Option<String>) -> Result<(), String> {
    if is_unsafe_path(&path) {
        return Err("非法路径".to_string());
    }

    let aid = agent_id.as_deref().unwrap_or("main");
    let candidates = [
        memory_dir_for_agent(aid, "memory").await,
        memory_dir_for_agent(aid, "archive").await,
        memory_dir_for_agent(aid, "core").await,
    ];

    for c in &candidates {
        if let Ok(dir) = c {
            let full = dir.join(&path);
            if full.exists() {
                return fs::remove_file(&full)
                    .map_err(|e| format!("删除失败: {e}"));
            }
        }
    }

    Err(format!("文件不存在: {path}"))
}

#[tauri::command]
pub async fn export_memory_zip(category: String, agent_id: Option<String>) -> Result<String, String> {
    let aid = agent_id.as_deref().unwrap_or("main");
    let dir = memory_dir_for_agent(aid, &category).await?;
    if !dir.exists() {
        return Err("目录不存在".to_string());
    }

    let mut files = Vec::new();
    collect_files(&dir, &dir, &mut files, &category)?;
    if files.is_empty() {
        return Err("没有可导出的文件".to_string());
    }

    let tmp_dir = std::env::temp_dir();
    let zip_name = format!(
        "openclaw-{}-{}.zip",
        category,
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    );
    let zip_path = tmp_dir.join(&zip_name);

    let file = fs::File::create(&zip_path)
        .map_err(|e| format!("创建 zip 失败: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for rel_path in &files {
        let full_path = dir.join(rel_path);
        let content = fs::read_to_string(&full_path)
            .map_err(|e| format!("读取 {rel_path} 失败: {e}"))?;
        zip.start_file(rel_path, options)
            .map_err(|e| format!("写入 zip 失败: {e}"))?;
        zip.write_all(content.as_bytes())
            .map_err(|e| format!("写入内容失败: {e}"))?;
    }

    zip.finish().map_err(|e| format!("完成 zip 失败: {e}"))?;
    Ok(zip_path.to_string_lossy().to_string())
}
