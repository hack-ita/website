const fs = require("fs");
const path = require("path");

// Configuration
const CONTENT_DIR = "./content/articoli"; // Adjust this path to your articoli directory
const DRY_RUN = false; // Set to true to preview changes without modifying files

/**
 * Converts a string to a URL-safe slug
 */
function toSlug(text) {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, "") // Remove non-word chars except spaces and hyphens
    .replace(/[\s_-]+/g, "-") // Replace spaces, underscores, hyphens with single hyphen
    .replace(/^-+|-+$/g, ""); // Remove leading/trailing hyphens
}

/**
 * Extracts the title from front matter
 */
function extractTitle(content) {
  // Match YAML front matter
  const yamlMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (yamlMatch) {
    const frontMatter = yamlMatch[1];

    // Check for multi-line title (>- or > or |)
    const multiLineTitleMatch = frontMatter.match(
      /title:\s*[>|][-+]?\s*\n((?:[ \t]+.+\n?)*)/,
    );
    if (multiLineTitleMatch) {
      // Extract all indented lines and join them
      const lines = multiLineTitleMatch[1]
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
      return lines.join(" ").trim();
    }

    // Check for single-line title
    const singleLineTitleMatch = frontMatter.match(
      /title:\s*["']?([^"'\n]+)["']?/,
    );
    if (singleLineTitleMatch) {
      return singleLineTitleMatch[1].trim();
    }
  }

  // Match TOML front matter
  const tomlMatch = content.match(/^\+\+\+\s*\n([\s\S]*?)\n\+\+\+/);
  if (tomlMatch) {
    const titleMatch = tomlMatch[1].match(/title\s*=\s*["']([^"']+)["']/);
    if (titleMatch) {
      return titleMatch[1].trim();
    }
  }

  return null;
}

/**
 * Checks if slug already exists in front matter
 */
function hasSlug(content) {
  return (
    /^(---[\s\S]*?\n---|\+\+\+[\s\S]*?\n\+\+\+)/m.test(content) &&
    /slug:\s*["']?[^"'\n]+["']?/m.test(content)
  );
}

/**
 * Adds slug to YAML or TOML front matter
 */
function addSlugToFrontMatter(content, slug) {
  // Handle YAML front matter
  if (content.startsWith("---")) {
    return content.replace(
      /^(---\s*\n[\s\S]*?)(\n---)/,
      `$1\nslug: "${slug}"$2`,
    );
  }

  // Handle TOML front matter
  if (content.startsWith("+++")) {
    return content.replace(
      /^(\+\+\+\s*\n[\s\S]*?)(\n\+\+\+)/,
      `$1\nslug = "${slug}"$2`,
    );
  }

  return content;
}

/**
 * Processes a single markdown file
 */
function processFile(filePath) {
  const content = fs.readFileSync(filePath, "utf8");

  // Skip if slug already exists
  if (hasSlug(content)) {
    console.log(`⏭️  Skipped (already has slug): ${filePath}`);
    return;
  }

  // Extract title
  const title = extractTitle(content);
  if (!title) {
    console.log(`⚠️  Warning: No title found in ${filePath}`);
    return;
  }

  // Get first word and convert to slug
  const firstWord = title.split(/\s+/)[0];
  const slug = toSlug(firstWord);

  if (!slug) {
    console.log(
      `⚠️  Warning: Could not generate slug from "${firstWord}" in ${filePath}`,
    );
    return;
  }

  // Add slug to content
  const updatedContent = addSlugToFrontMatter(content, slug);

  if (DRY_RUN) {
    console.log(`🔍 [DRY RUN] Would add slug "${slug}" to: ${filePath}`);
  } else {
    fs.writeFileSync(filePath, updatedContent, "utf8");
    console.log(`✅ Added slug "${slug}" to: ${filePath}`);
  }
}

/**
 * Recursively processes all markdown files in a directory
 */
function processDirectory(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      // Recursively process subdirectories
      processDirectory(fullPath);
    } else if (
      entry.isFile() &&
      entry.name.endsWith(".md") &&
      entry.name !== "_index.md"
    ) {
      // Process markdown files (except _index.md)
      processFile(fullPath);
    }
  }
}

/**
 * Main execution
 */
function main() {
  if (!fs.existsSync(CONTENT_DIR)) {
    console.error(`❌ Error: Directory not found: ${CONTENT_DIR}`);
    console.log(
      "Please update the CONTENT_DIR variable in the script to point to your articoli directory.",
    );
    process.exit(1);
  }

  console.log(`\n🚀 Starting slug generation for: ${CONTENT_DIR}`);
  console.log(
    `📝 Mode: ${
      DRY_RUN
        ? "DRY RUN (no files will be modified)"
        : "LIVE (files will be modified)"
    }\n`,
  );

  processDirectory(CONTENT_DIR);

  console.log("\n✨ Done!\n");

  if (DRY_RUN) {
    console.log(
      "ℹ️  This was a dry run. Set DRY_RUN = false to actually modify files.",
    );
  }
}

// Run the script
main();