import { Collection } from "tinacms";

const About: Collection = {
  name: "about",
  label: "About Page",

  // MUST be a directory
  path: "content/about",
  format: "md",

  // Single-file only
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
     * Main Content Section
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
     * Cards Section
     * ===================== */

    {
      type: "object",
      name: "cards",
      label: "Cards Section",
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
          type: "object",
          name: "card",
          label: "Cards",
          list: true,
          fields: [
            {
              type: "string",
              name: "title",
              label: "Card Title",
              required: true,
            },
            {
              type: "string",
              name: "content",
              label: "Card Content",
              ui: {
                component: "textarea",
              },
            },
          ],
        },
      ],
    },

    /* =====================
     * Extra Content Section
     * ===================== */

    {
      type: "object",
      name: "extra_content",
      label: "Extra Content",
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
     * FAQs Section
     * ===================== */

    {
      type: "object",
      name: "faqs",
      label: "FAQs Section",
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
          type: "object",
          name: "faq",
          label: "FAQ Items",
          list: true,
          fields: [
            {
              type: "string",
              name: "title",
              label: "Question",
              required: true,
            },
            {
              type: "string",
              name: "content",
              label: "Answer",
              ui: {
                component: "textarea",
              },
            },
          ],
        },
      ],
    },
  ],
};

export default About;
