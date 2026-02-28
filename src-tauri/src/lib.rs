mod commands;
mod models;

use commands::{config, extensions, logs, memory, service};

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            // 配置
            config::read_openclaw_config,
            config::write_openclaw_config,
            config::read_mcp_config,
            config::write_mcp_config,
            config::get_version_info,
            config::check_installation,
            config::write_env_file,
            config::list_backups,
            config::create_backup,
            config::restore_backup,
            config::delete_backup,
            config::reload_gateway,
            config::test_model,
            config::list_remote_models,
            config::upgrade_openclaw,
            config::install_gateway,
            config::uninstall_gateway,
            config::get_npm_registry,
            config::set_npm_registry,
            // 服务
            service::get_services_status,
            service::start_service,
            service::stop_service,
            service::restart_service,
            // 日志
            logs::read_log_tail,
            logs::search_log,
            // 记忆文件
            memory::list_memory_files,
            memory::read_memory_file,
            memory::write_memory_file,
            memory::delete_memory_file,
            memory::export_memory_zip,
            // 扩展工具
            extensions::get_cftunnel_status,
            extensions::cftunnel_action,
            extensions::get_cftunnel_logs,
            extensions::get_clawapp_status,
            extensions::install_cftunnel,
        ])
        .run(tauri::generate_context!())
        .expect("启动 ClawPanel 失败");
}
