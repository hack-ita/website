import { defineConfig } from "tinacms";
import BaseSettings from "./collections/base";
import MenuSettings from "./collections/menus";
import ParamSettings from "./collections/params";
import Home from "./collections/home";
import About from "./collections/about";
import BlogIndex from "./collections/blog-index";
import Blog from "./collections/blog";
import ServicesIndex from "./collections/services-index";
import Services from "./collections/services";
import CategoriesIndex from "./collections/categories-index";
import Categories from "./collections/categories";

const branch = "main";

export default defineConfig({
  branch,

  clientId: process.env.TINA_CLIENT_ID,
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
      BaseSettings,
      MenuSettings,
      ParamSettings,
      Home,
      About,
      ServicesIndex,
      Services,
      BlogIndex,
      Blog,
      CategoriesIndex,
      Categories,
    ],
  },
});
