import { Collection } from "tinacms";

const ParamSettings: Collection = {
  name: "paramSettings",
  label: "Params",
  path: "config/_default",
  format: "yaml",
  match: { include: "params" }, // only params.yaml
  ui: { allowedActions: { create: false, delete: false } },
  fields: [
    { type: "number", name: "reading_speed", label: "Reading Speed" },
    {
      type: "object",
      name: "header",
      label: "Header Params",
      fields: [
        { type: "image", name: "logo", label: "Logo" },
        {
          type: "object",
          name: "cta",
          label: "CTA Button",
          fields: [
            { type: "boolean", name: "enable", label: "Enable CTA" },
            { type: "string", name: "label", label: "CTA Label" },
            { type: "string", name: "link", label: "CTA Link" },
          ],
        },
      ],
    },
    {
      type: "object",
      name: "footer",
      label: "Footer Params",
      fields: [
        { type: "image", name: "logo", label: "Footer Logo" },
        { type: "string", name: "disclaimer", label: "Disclaimer" },
      ],
    },
    {
      type: "object",
      name: "social",
      label: "Social Links",
      fields: [
        { type: "string", name: "facebook", label: "Facebook URL" },
        { type: "string", name: "instagram", label: "Instagram URL" },
        { type: "string", name: "twitter", label: "Twitter/X URL" },
        { type: "string", name: "linkedin", label: "LinkedIn URL" },
      ],
    },
  ],
};

export default ParamSettings;