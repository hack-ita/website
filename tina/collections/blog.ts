import { Collection } from "tinacms";

const Blog: Collection = {
  name: "blog",
  label: "Blog Posts",

  path: "content/blog",
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
      label: "Featured Image",
    },
    {
      type: "string",
      name: "categories",
      label: "Categories",
      list: true,
    },
    {
      type: "string",
      name: "subcategories",
      label: "Sub Categories",
      list: true,
    },
    {
      type: "string",
      name: "tags",
      label: "Tags",
      list: true,
    },
    {
      type: "boolean",
      name: "featured",
      label: "Featured",
    },

    /* =====================
     * Post Body
     * ===================== */

    {
      type: "string",
      name: "body",
      label: "Content",
      isBody: true,
      ui: {
        component: "textarea",
      },
    },
  ],
};

export default Blog;