import { defineConfig } from "tinacms";
import Home from "./collections/home";
import About from "./collections/about";
import BlogIndex from "./collections/blog-index";
import Blog from "./collections/blog";
import ServicesIndex from "./collections/services-index";
import Services from "./collections/services";

const branch =
  process.env.GITHUB_BRANCH ||
  process.env.VERCEL_GIT_COMMIT_REF ||
  process.env.HEAD ||
  "main";

export default defineConfig({
  branch,

  clientId: process.env.NEXT_PUBLIC_TINA_CLIENT_ID,
  token: process.env.TINA_TOKEN,

  build: {
    outputFolder: "admin",
    publicFolder: "public",
  },

  media: {
    tina: {
      mediaRoot: "",
      publicFolder: "static",
    },
  },

  schema: {
    collections: [
      Home,
      About,
      ServicesIndex,
      Services,
      BlogIndex,
      Blog,
    ],
  },
});