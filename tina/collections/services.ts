import { Collection } from "tinacms";

const Services: Collection = {
  name: "services",
  label: "Service Pages",

  path: "content/servizi",
  format: "md",

  match: {
    exclude: "_index",
  },

  fields: [
    {
      type: "string",
      name: "title",
      label: "Service Title",
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

    /* =====================
     * Page Body
     * ===================== */

    {
      label: "Content",
      name: "body",
      isBody: true,
      type: "rich-text",
    },
  ],
};

export default Services;
