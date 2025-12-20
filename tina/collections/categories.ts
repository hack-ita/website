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
  ],
};

export default Categories;