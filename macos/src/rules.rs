//! 进程规则匹配。
//!
//! ProcSocks 的规则语义是「对**可执行文件完整路径**做正则搜索」——`codex.exe`
//! 这样的简单规则能匹配到路径里含有该名字的程序。这个语义在 Windows 上由
//! NetFilter 驱动内部实现，在 macOS 上必须由我们自己实现，因为 pf 只能按
//! 用户匹配，没法按进程匹配。
//!
//! 两个平台共享同一份配置，所以这里的匹配语义刻意保持与 Windows 一致：
//! **大小写敏感**（需要忽略大小写就写 `(?i)`），并且是**搜索**而不是全串匹配。

use anyhow::{Context, Result};
use regex::Regex;

/// 编译好的规则集合。
pub struct RuleSet {
    process: Vec<Regex>,
    bypass: Vec<Regex>,
}

impl RuleSet {
    /// 编译 `processPatterns` 与 `bypassPatterns`。
    ///
    /// 会自动把**本进程自己的可执行路径**加进 bypass——即使使用者不小心写了
    /// 一条能匹配到 procsocks 的规则，也绝不会把代理自己卷进去。这条在 Windows
    /// 后端里也有一份（那 边是把程序名塞给驱动的 bypass 列表）。
    pub fn compile(process_patterns: &[String], bypass_patterns: &[String]) -> Result<Self> {
        let mut bypass = compile_all(bypass_patterns, "bypassPatterns")?;

        if let Ok(current) = std::env::current_exe() {
            let literal = regex::escape(&current.to_string_lossy());
            let anchored = Regex::new(&format!("^{literal}$"))
                .context("failed to compile the self-bypass pattern")?;
            bypass.push(anchored);
        }

        Ok(Self {
            process: compile_all(process_patterns, "processPatterns")?,
            bypass,
        })
    }

    /// 这条可执行路径该不该走代理。
    ///
    /// 生产路径统一走 [`RuleSet::explain`]（它顺便给出命中的规则用于日志），
    /// 这里只作为更直白的断言接口供测试使用。
    #[cfg(test)]
    pub fn should_proxy(&self, executable: &str) -> bool {
        self.explain(executable).0
    }

    /// 命中的具体规则，用于日志。返回 `(是否代理, 命中的规则)`。
    pub fn explain(&self, executable: &str) -> (bool, Option<String>) {
        for rule in &self.bypass {
            if rule.is_match(executable) {
                return (false, Some(format!("bypass {}", rule.as_str())));
            }
        }
        for rule in &self.process {
            if rule.is_match(executable) {
                return (true, Some(format!("process {}", rule.as_str())));
            }
        }
        (false, None)
    }
}

fn compile_all(patterns: &[String], field: &str) -> Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).with_context(|| format!("invalid {field} regex {pattern:?}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::RuleSet;

    fn rules(process: &[&str], bypass: &[&str]) -> RuleSet {
        let process: Vec<String> = process.iter().map(|s| s.to_string()).collect();
        let bypass: Vec<String> = bypass.iter().map(|s| s.to_string()).collect();
        RuleSet::compile(&process, &bypass).expect("rules should compile")
    }

    #[test]
    fn matches_a_bare_executable_name_against_the_full_path() {
        // 这是 ProcSocks README 里承诺的语义：简单规则能匹配完整路径中的子串。
        let set = rules(&["ChatGPT"], &[]);
        assert!(set.should_proxy("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"));
        assert!(!set.should_proxy("/usr/bin/curl"));
    }

    #[test]
    fn bypass_wins_over_process() {
        let set = rules(&["ChatGPT"], &["ChatGPT.app/Contents/MacOS/ChatGPT$"]);
        assert!(!set.should_proxy("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"));
    }

    #[test]
    fn default_self_bypass_does_not_bypass_apps_in_a_procsocks_project_directory() {
        let config = crate::config::Config::example();
        let set = RuleSet::compile(&[".*".to_string()], &config.bypass_patterns).unwrap();
        assert!(set.should_proxy(
            "/Users/user/procsocks-mac/dist/ProcSocks Network Test.app/Contents/MacOS/ProcSocksNetworkTest"
        ));
        #[cfg(not(windows))]
        assert!(!set.should_proxy("/Library/Application Support/ProcSocks/procsocks"));
        #[cfg(windows)]
        assert!(!set.should_proxy(r"C:\Program Files\ProcSocks\procsocks.exe"));
    }

    #[test]
    fn an_empty_process_list_proxies_nothing() {
        let set = rules(&[], &[]);
        assert!(!set.should_proxy("/usr/bin/curl"));
    }

    #[test]
    fn matching_is_case_sensitive_by_default() {
        let set = rules(&["chatgpt"], &[]);
        assert!(!set.should_proxy("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"));
        let insensitive = rules(&["(?i)chatgpt"], &[]);
        assert!(insensitive.should_proxy("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"));
    }

    #[test]
    fn the_proxy_never_proxies_itself() {
        // 自动注入的自我 bypass 必须挡住本进程自己的可执行路径。
        let current = std::env::current_exe().expect("test binary path");
        let set = rules(&[".*"], &[]);
        assert!(
            !set.should_proxy(&current.to_string_lossy()),
            "the self-bypass pattern should protect {}",
            current.display()
        );
    }

    #[test]
    fn explain_reports_the_matched_rule() {
        let set = rules(&["curl"], &[]);
        let (proxy, reason) = set.explain("/usr/bin/curl");
        assert!(proxy);
        assert_eq!(reason.as_deref(), Some("process curl"));

        let (proxy, reason) = set.explain("/usr/bin/ssh");
        assert!(!proxy);
        assert!(reason.is_none());
    }

    #[test]
    fn rejects_invalid_regex() {
        let broken = vec!["(unclosed".to_string()];
        assert!(RuleSet::compile(&broken, &[]).is_err());
        assert!(RuleSet::compile(&[], &broken).is_err());
    }
}
