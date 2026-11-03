# AI Agent Skills

This directory contains reusable AI agent skills for common CMO workflows.
Skills provide structured, step-by-step instructions that AI coding agents
can load on demand.

## Available skills

| Skill | Description |
|-------|-------------|
| [add-telemetry-signal](add-telemetry-signal/) | Add or modify a metric in OCP Telemetry |

## Using skills with your AI coding agent

Skills use the [SKILL.md format](https://agentskills.io) with YAML
frontmatter (`name` + `description`). Most AI coding agents discover them
automatically from well-known directories. Since this repo stores skills in
`Documentation/skills/`, you need to link them into your agent's search
path.

### OpenCode

Symlink into the project-local `.opencode/skills/` directory:

```bash
mkdir -p .opencode/skills
ln -s ../../Documentation/skills/add-telemetry-signal .opencode/skills/add-telemetry-signal
```

Or into the global directory to make it available across all projects:

```bash
ln -s /path/to/cluster-monitoring-operator/Documentation/skills/add-telemetry-signal \
  ~/.config/opencode/skills/add-telemetry-signal
```

Discovery paths: `.opencode/skills/*/SKILL.md`, `~/.config/opencode/skills/*/SKILL.md`

### Claude Code

Symlink into `.claude/skills/`:

```bash
mkdir -p .claude/skills
ln -s ../../Documentation/skills/add-telemetry-signal .claude/skills/add-telemetry-signal
```

Or globally:

```bash
ln -s /path/to/cluster-monitoring-operator/Documentation/skills/add-telemetry-signal \
  ~/.claude/skills/add-telemetry-signal
```

Discovery paths: `.claude/skills/*/SKILL.md`, `~/.claude/skills/*/SKILL.md`

### Cursor

Symlink into `.cursor/skills/` or `.agents/skills/`:

```bash
mkdir -p .cursor/skills
ln -s ../../Documentation/skills/add-telemetry-signal .cursor/skills/add-telemetry-signal
```

Or globally:

```bash
ln -s /path/to/cluster-monitoring-operator/Documentation/skills/add-telemetry-signal \
  ~/.cursor/skills/add-telemetry-signal
```

Discovery paths: `.cursor/skills/*/SKILL.md`, `.agents/skills/*/SKILL.md`,
`~/.cursor/skills/*/SKILL.md`

Cursor also reads from `.claude/skills/` for compatibility.

### Other agents

Any agent that supports the [Agent Skills](https://agentskills.io) open
standard can use these skills. Place a symlink in the agent's skill
discovery path pointing to the skill directory.

## Adding a new skill

1. Create a directory under `Documentation/skills/<skill-name>/`.
2. Add a `SKILL.md` with YAML frontmatter:
   ```yaml
   ---
   name: skill-name
   description: >-
     Short description of what the skill does and when to use it.
   ---
   ```
3. The `name` must match the directory name, be lowercase alphanumeric
   with single-hyphen separators, and be 1-64 characters.
4. Optionally add supporting files (templates, schemas, examples) in the
   same directory.
5. Update the table in this README.
