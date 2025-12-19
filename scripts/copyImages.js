const fs = require("fs");
const path = require("path");
const fse = require("fs-extra");

const srcDir = path.join(process.cwd(), "static/images");
const destDir = path.join(process.cwd(), "assets/images");

// Allowed image extensions
const IMAGE_EXTS = [".jpg", ".jpeg", ".png", ".webp", ".avif", ".gif"];

function copyImages(src, dest) {
  if (!fs.existsSync(src)) {
    console.warn(`Source directory not found: ${src}`);
    return;
  }

  if (fs.existsSync(dest)) {
    fse.removeSync(dest);
    console.log("Previous assets/images folder removed.");
  }

  let copiedFiles = 0;

  fse.copySync(src, dest, {
    filter: (srcPath) => {
      const stat = fs.statSync(srcPath);
      if (stat.isDirectory()) return true;
      const ext = path.extname(srcPath).toLowerCase();
      if (IMAGE_EXTS.includes(ext)) {
        copiedFiles++;
        return true;
      }
      return false;
    },
  });

  console.log(`Copied ${copiedFiles} image(s) from ${src} → ${dest}`);
}

try {
  copyImages(srcDir, destDir);
  console.log("Prebuild image processing ready for Hugo.");
} catch (err) {
  console.error("Error in prebuild image copy:", err);
  process.exit(1);
}