//! Loader for markdown skill files with optional YAML-style frontmatter.
//!
//! A skill file may start with a frontmatter block delimited by `---`:
//!
//! ```text
//! ---
//! name: code-review
//! allowed_tools: [fs_read, echo]
//! ---
//! # Instructions
//! Review the code ...
//! ```
//!
//! When no frontmatter is present the file stem becomes the name and the whole
//! file becomes the prompt.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skill {
    pub name: String,
    pub prompt: String,
    pub allowed_tools: Vec<String>,
}

impl Skill {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub fn allowed_tools(&self) -> &[String] {
        &self.allowed_tools
    }

    pub fn allows_tool(&self, tool: &str) -> bool {
        self.allowed_tools
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(tool))
    }
}

/// Loads skills from a directory of `.md` files.
#[derive(Debug, Clone, Default)]
pub struct SkillLoader {
    skills: Vec<Skill>,
}

impl SkillLoader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load every markdown file in a directory (non-recursive), sorted by file
    /// name for deterministic ordering.
    pub fn load_dir(path: impl AsRef<Path>) -> Result<Self> {
        let dir = path.as_ref();
        let entries = fs::read_dir(dir)
            .with_context(|| format!("reading skill directory {}", dir.display()))?;
        let mut files: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
            })
            .collect();
        files.sort();
        let mut skills = Vec::with_capacity(files.len());
        for file in files {
            skills.push(SkillLoader::load_file(&file)?);
        }
        Ok(Self { skills })
    }

    /// Load a single markdown skill file.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Skill> {
        let file = path.as_ref();
        let text = fs::read_to_string(file)
            .with_context(|| format!("reading skill file {}", file.display()))?;
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("skill")
            .to_string();
        Ok(parse_skill(&stem, &text))
    }

    pub fn skills(&self) -> &[Skill] {
        &self.skills
    }

    pub fn names(&self) -> Vec<String> {
        self.skills.iter().map(|skill| skill.name.clone()).collect()
    }

    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.skills
            .iter()
            .find(|skill| skill.name.eq_ignore_ascii_case(name))
    }

    /// Concatenate skill prompts into a single system-prompt fragment.
    pub fn combined_prompt(&self) -> String {
        self.skills
            .iter()
            .map(|skill| format!("# {}\n\n{}", skill.name, skill.prompt))
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    pub fn len(&self) -> usize {
        self.skills.len()
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }
}

/// Convenience free function returning the skills directly.
pub fn load_skills(path: impl AsRef<Path>) -> Result<Vec<Skill>> {
    Ok(SkillLoader::load_dir(path)?.skills)
}

fn parse_skill(stem: &str, text: &str) -> Skill {
    let lines: Vec<&str> = text.lines().collect();
    let mut cursor = 0usize;
    let mut name = stem.to_string();
    let mut allowed_tools = Vec::new();

    if lines.first().is_some_and(|line| line.trim() == "---") {
        if let Some(end) = lines[1..].iter().position(|line| line.trim() == "---") {
            let frontmatter = &lines[1..1 + end];
            name = frontmatter
                .iter()
                .find_map(|line| line.strip_prefix("name:"))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(stem)
                .to_string();
            allowed_tools = parse_allowed_tools(frontmatter);
            cursor = end + 2;
        }
    }

    let prompt = lines[cursor..].join("\n").trim().to_string();
    Skill {
        name,
        prompt,
        allowed_tools,
    }
}

fn parse_allowed_tools(frontmatter: &[&str]) -> Vec<String> {
    let mut tools = Vec::new();
    let mut in_list = false;
    for line in frontmatter {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("allowed_tools:") {
            let value = value.trim();
            if value.starts_with('[') && value.ends_with(']') {
                tools.extend(
                    value[1..value.len() - 1]
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(str::to_string),
                );
            } else if !value.is_empty() {
                tools.push(value.to_string());
            }
            in_list = value.is_empty();
            continue;
        }
        if in_list {
            if let Some(item) = trimmed.strip_prefix('-') {
                let item = item.trim();
                if !item.is_empty() {
                    tools.push(item.to_string());
                }
                continue;
            }
            if trimmed.contains(':') {
                in_list = false;
            }
        }
    }
    tools
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frontmatter_and_plain_files() {
        let dir = std::env::temp_dir().join(format!("minibug-skills-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("review.md"),
            "---\nname: code-review\nallowed_tools: [fs_read, echo]\n---\n# Review\nLook for bugs.\n",
        )
        .unwrap();
        fs::write(dir.join("plain.md"), "Just a prompt.").unwrap();
        fs::write(dir.join("ignore.txt"), "not a skill").unwrap();

        let loader = SkillLoader::load_dir(&dir).unwrap();
        assert_eq!(loader.len(), 2);
        let review = loader.get("code-review").unwrap();
        assert_eq!(review.allowed_tools, vec!["fs_read", "echo"]);
        assert!(review.allows_tool("FS_READ"));
        assert!(review.prompt().contains("Look for bugs"));
        assert_eq!(loader.get("plain").unwrap().prompt(), "Just a prompt.");
        assert!(loader.combined_prompt().contains("code-review"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parses_multiline_allowlist() {
        let skill = parse_skill(
            "fallback",
            "---\nname: scan\nallowed_tools:\n  - dns\n  - http_request\ndescription: ignored\n---\nbody",
        );
        assert_eq!(skill.name, "scan");
        assert_eq!(skill.allowed_tools, vec!["dns", "http_request"]);
        assert_eq!(skill.prompt, "body");
    }
}
