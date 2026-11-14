//! 科研数据脱敏平台核心库。
//! 服务端入口在 `main.rs`，此处导出可测试的内部模块。

pub mod api;
pub mod audit;
pub mod csvio;
pub mod db;
pub mod detect;
pub mod detection_eval;
pub mod engine;
pub mod models;
pub mod release;
pub mod state;
pub mod synth;
pub mod util;
