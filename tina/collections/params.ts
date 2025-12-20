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
      fields: [{ type: "image", name: "logo", label: "Logo" }],
    },
  ],
};

export default ParamSettings;