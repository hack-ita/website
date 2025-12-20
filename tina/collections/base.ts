import { Collection } from "tinacms";

const BaseSettings: Collection = {
  name: "baseSettings",
  label: "Base Settings",
  path: "config/_default",
  format: "yaml",
  match: { include: "hugo" }, // only hugo.yaml
  ui: { allowedActions: { create: false, delete: false } },
  fields: [
    { type: "string", name: "baseURL", label: "Base URL" },
    { type: "string", name: "languageCode", label: "Language Code" },
    { type: "string", name: "title", label: "Site Title" },
  ],
};

export default BaseSettings;