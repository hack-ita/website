import { Collection } from "tinacms";

const Home: Collection = {
  name: "home",
  label: "Home Page",

  // MUST be a directory
  path: "content",
  format: "md",

  // Restrict this collection to ONLY _index.md
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
      label: "Meta Description (SEO)",
      description:
        "Shown in Google results and as the homepage meta description (~150-160 characters).",
      ui: { component: "textarea" },
    },

    /* =====================
     * About Section
     * ===================== */

    {
      type: "object",
      name: "about",
      label: "About Section",
      fields: [
        {
          type: "boolean",
          name: "enable",
          label: "Enable About Section",
        },
        {
          type: "image",
          name: "image",
          label: "About Image",
        },
        {
          type: "string",
          name: "title",
          label: "About Title",
        },
        {
          type: "string",
          name: "content",
          label: "About Content",
          ui: {
            component: "textarea",
          },
        },
      ],
    },
  ],
};

export default Home;