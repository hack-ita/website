import { Collection } from "tinacms";

const Categories: Collection = {
  name: "categories",
  label: "Category Pages",

  path: "content/categories",
  format: "md",

  match: {
    exclude: "_index",
  },

  fields: [
    {
      type: "string",
      name: "title",
      label: "Title",
      isTitle: true,
      required: true,
    },
    {
      type: "number",
      name: "weight",
      label: "Order",
      required: false,
    },
    {
      type: "string",
      name: "url",
      label: "URL",
      description: "Custom permalink for this category (e.g. categorie/cve).",
    },
    {
      type: "string",
      name: "hero_title",
      label: "Hero Title",
    },
    {
      type: "string",
      name: "description",
      label: "Description",
      ui: {
        component: "textarea",
      },
    },
    {
      type: "image",
      name: "image",
      label: "Category Image",
    },
    {
      type: "string",
      name: "tags",
      label: "Tags",
      list: true,
    },
    {
      type: "string",
      name: "subcategories",
      label: "Subcategories",
      list: true,
    },
  ],
};

export default Categories;