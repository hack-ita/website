import { Collection } from "tinacms";

const MenuSettings: Collection = {
  name: "menuSettings",
  label: "Menus",
  path: "config/_default",
  format: "yaml",
  match: { include: "menus" }, // only menus.yaml
  ui: { allowedActions: { create: false, delete: false } },
  fields: [
    {
      type: "object",
      name: "main",
      label: "Main Menu",
      list: true,
      fields: [
        { type: "string", name: "name", label: "Name" },
        { type: "string", name: "pageRef", label: "Page Reference" },
        { type: "number", name: "weight", label: "Order" },
      ],
    },
    {
      type: "object",
      name: "footer",
      label: "Footer Menu",
      list: true,
      fields: [
        { type: "string", name: "name", label: "Name" },
        { type: "string", name: "pageRef", label: "Page Reference" },
        { type: "number", name: "weight", label: "Order" },
      ],
    },
  ],
};

export default MenuSettings;