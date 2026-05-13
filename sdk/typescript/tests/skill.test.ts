import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { dirname, join, resolve } from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { loadSkill, loadAll, extract, validate } from "../src/index.js";

function repoRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  let dir = resolve(here);
  while (dir !== "/" && dir.length > 1) {
    if (
      existsSync(join(dir, "manifest.json")) &&
      existsSync(join(dir, "skills"))
    ) {
      return dir;
    }
    dir = dirname(dir);
  }
  throw new Error("could not locate repo root from " + here);
}

describe("skillslib", () => {
  const root = repoRoot();

  it("loads secret-detection", () => {
    const s = loadSkill(join(root, "skills", "secret-detection", "SKILL.md"));
    assert.equal(s.frontmatter.id, "secret-detection");
    assert.ok(s.frontmatter.version);
    assert.ok(s.frontmatter.token_budget.minimal > 0);
  });

  it("loads at least 20 skills", () => {
    const all = loadAll(join(root, "skills"));
    assert.ok(all.length >= 20, `expected >= 20 skills, got ${all.length}`);
  });

  it("validates a real skill with no errors", () => {
    const s = loadSkill(join(root, "skills", "secret-detection", "SKILL.md"));
    assert.deepEqual(validate(s), []);
  });

  it("orders tiers minimal <= compact <= full", () => {
    const s = loadSkill(join(root, "skills", "secret-detection", "SKILL.md"));
    const mini = extract(s, "minimal");
    const compact = extract(s, "compact");
    const full = extract(s, "full");
    assert.ok(mini.length > 0);
    assert.ok(compact.length >= mini.length);
    assert.ok(full.length >= compact.length);
  });

  it("rejects unknown tier", () => {
    const s = loadSkill(join(root, "skills", "secret-detection", "SKILL.md"));
    assert.throws(() => extract(s, "ginormous" as never));
  });
});
