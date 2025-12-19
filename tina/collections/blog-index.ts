import { Collection } from "tinacms";

const BlogIndex: Collection = {
  name: "blogIndex",
  label: "Blog Page",

  path: "content/blog",
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

export default BlogIndex;
