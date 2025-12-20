import { Collection } from "tinacms";

const CategoriesIndex: Collection = {
  name: "categoriesIndex",
  label: "Categories Page",

  path: "content/categories",
  format: "md",

  match: {
    include: "_index",
  },

  ui: {
    allowedActions: {
      create: false,
      delete: false,
    },
  },

  fields: [
    {
      type: "string",
      name: "title",
      label: "Page Title",
      isTitle: true,
      required: true,
    },
    {
      type: "string",
      name: "hero_title",
      label: "Hero Title",
      required: false,
    },
    {
      type: "string",
      name: "description",
      label: "Page Description",
      ui: {
        component: "textarea",
      },
    },
    {
      type: "image",
      name: "image",
      label: "Featured Image",
    },
  ],
};

export default CategoriesIndex;