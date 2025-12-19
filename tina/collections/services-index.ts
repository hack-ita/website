import { Collection } from "tinacms";

const ServicesIndex: Collection = {
  name: "servicesIndex",
  label: "Services Page",

  path: "content/services",
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
      type: "image",
      name: "image",
      label: "Featured Image",
    },

    /* =====================
     * Content Section
     * ===================== */

    {
      type: "object",
      name: "content",
      label: "Main Content",
      fields: [
        {
          type: "boolean",
          name: "enable",
          label: "Enable Section",
        },
        {
          type: "string",
          name: "title",
          label: "Section Title",
        },
        {
          type: "string",
          name: "content",
          label: "Section Content",
          ui: {
            component: "textarea",
          },
        },
      ],
    },

    /* =====================
     * Stats Section
     * ===================== */

    {
      type: "object",
      name: "stats",
      label: "Stats Section",
      fields: [
        {
          type: "boolean",
          name: "enable",
          label: "Enable Section",
        },
        {
          type: "string",
          name: "title",
          label: "Stats Title",
        },
      ],
    },
  ],
};

export default ServicesIndex;
