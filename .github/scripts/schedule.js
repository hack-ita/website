const fs = require("fs");
const path = require("path");
const matter = require("gray-matter");
const { parseISO, startOfDay } = require("date-fns");
const { formatInTimeZone } = require("date-fns-tz");

// Root folder for your blog posts
const postsDir = path.join(__dirname, "../../content/articoli");

// Helper to read all markdown files recursively
function getMarkdownFiles(dir) {
  let files = [];
  try {
    fs.readdirSync(dir).forEach((file) => {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        files = files.concat(getMarkdownFiles(fullPath));
      } else if (file.endsWith(".md")) {
        files.push(fullPath);
      }
    });
  } catch (error) {
    console.error(`Error reading directory ${dir}:`, error.message);
  }
  return files;
}

// Get current date/time in Italy timezone
const ITALY_TZ = "Europe/Rome";
const now = new Date();
const italyNow = formatInTimeZone(now, ITALY_TZ, "yyyy-MM-dd HH:mm:ss");
const todayItaly = startOfDay(
  new Date(formatInTimeZone(now, ITALY_TZ, "yyyy-MM-dd")),
);

console.log("=".repeat(60));
console.log("📅 SCHEDULED POST PUBLISHER");
console.log("=".repeat(60));
console.log(`⏰ Current time (Italy): ${italyNow}`);
console.log(
  `📆 Publishing posts scheduled for: ${formatInTimeZone(
    todayItaly,
    ITALY_TZ,
    "yyyy-MM-dd",
  )} or earlier`,
);
console.log("=".repeat(60));

const files = getMarkdownFiles(postsDir);

if (files.length === 0) {
  console.log("⚠️  No markdown files found in", postsDir);
  process.exit(0);
}

console.log(`📝 Found ${files.length} markdown file(s) to check\n`);

let publishedCount = 0;
let skippedCount = 0;
let errorCount = 0;

files.forEach((file) => {
  try {
    const content = fs.readFileSync(file, "utf8");
    const parsed = matter(content);
    const fileName = path.basename(file);

    // Only process draft posts with a date
    if (parsed.data.draft !== true) {
      return; // Already published, skip silently
    }

    if (!parsed.data.date) {
      console.log(`⚠️  ${fileName}: No date field found, skipping`);
      skippedCount++;
      return;
    }

    // Parse the date from frontmatter
    let postDate;
    if (typeof parsed.data.date === "string") {
      postDate = parseISO(parsed.data.date);
    } else if (parsed.data.date instanceof Date) {
      postDate = parsed.data.date;
    } else {
      console.log(
        `❌ ${fileName}: Invalid date format (${typeof parsed.data.date})`,
      );
      errorCount++;
      return;
    }

    // Validate parsed date
    if (isNaN(postDate.getTime())) {
      console.log(`❌ ${fileName}: Could not parse date "${parsed.data.date}"`);
      errorCount++;
      return;
    }

    const postDateStartOfDay = startOfDay(postDate);

    // Publish if scheduled for today or earlier
    if (postDateStartOfDay <= todayItaly) {
      parsed.data.draft = false;
      const newContent = matter.stringify(parsed.content, parsed.data);
      fs.writeFileSync(file, newContent);

      const scheduledDate = formatInTimeZone(postDate, ITALY_TZ, "yyyy-MM-dd");
      console.log(`✅ PUBLISHED: ${fileName}`);
      console.log(`   📅 Scheduled for: ${scheduledDate}`);
      publishedCount++;
    } else {
      const scheduledDate = formatInTimeZone(postDate, ITALY_TZ, "yyyy-MM-dd");
      console.log(
        `⏳ ${fileName}: Still scheduled for future (${scheduledDate})`,
      );
      skippedCount++;
    }
  } catch (error) {
    console.error(`❌ Error processing ${path.basename(file)}:`, error.message);
    errorCount++;
  }
});

// Summary
console.log("\n" + "=".repeat(60));
console.log("📊 SUMMARY");
console.log("=".repeat(60));
console.log(`✅ Published: ${publishedCount}`);
console.log(`⏳ Skipped (future): ${skippedCount}`);
console.log(`❌ Errors: ${errorCount}`);
console.log("=".repeat(60));

if (publishedCount === 0 && errorCount === 0) {
  console.log("\n✨ All good! No posts ready to publish today.");
  process.exit(0);
} else if (errorCount > 0) {
  console.log("\n⚠️  Completed with errors. Please review the output above.");
  process.exit(0); // Don't fail the workflow, just warn
} else {
  console.log(`\n🎉 Successfully published ${publishedCount} post(s)!`);
  process.exit(0);
}