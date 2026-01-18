const fs = require("fs");
const path = require("path");
const matter = require("gray-matter");

const { parseISO, isBefore } = require("date-fns");

// Root folder for your blog posts
const postsDir = path.join(__dirname, "../../content/articoli");

// Helper to read all markdown files recursively
function getMarkdownFiles(dir) {
  let files = [];
  fs.readdirSync(dir).forEach((file) => {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      files = files.concat(getMarkdownFiles(fullPath));
    } else if (file.endsWith(".md")) {
      files.push(fullPath);
    }
  });
  return files;
}

const now = new Date();
const files = getMarkdownFiles(postsDir);

files.forEach((file) => {
  const content = fs.readFileSync(file, "utf8");
  const parsed = matter(content);

  // Ensure postDate is a proper Date object
  const postDate = new Date(parsed.data.date);

  if (parsed.data.draft === true) {
    const now = new Date();
    if (postDate <= now) {
      parsed.data.draft = false;
      const newContent = matter.stringify(parsed.content, parsed.data);
      fs.writeFileSync(file, newContent);
      console.log(`Published: ${file}`);
    }
  }
});