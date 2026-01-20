import { Collection } from "tinacms";

const Blog: Collection = {
  name: "blog",
  label: "Blog Posts",

  path: "content/articoli",
  format: "md",

  match: {
    exclude: "_index",
  },

  fields: [
    {
      type: "string",
      name: "title",
      label: "Title",
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
    {
      type: "boolean",
      name: "draft",
      label: "Draft",
    },
    {
      type: "datetime",
      name: "date",
      label: "Publish Date",
      required: true,
      ui: {
        dateFormat: "YYYY-MM-DD",
      },
    },
    {
      type: "datetime",
      name: "lastmod",
      label: "Last Updated",
      ui: {
        dateFormat: "YYYY-MM-DD",
      },
    },

    /* =====================
     * Categories (Dropdown)
     * ===================== */
    {
      type: "string",
      name: "categories",
      label: "Categories",
      required: true,
      list: true,
      ui: {
        component: "select",
      },
      options: [
        { label: "CVE", value: "cve" },
        { label: "Guides & Resources", value: "guides-resources" },
        { label: "Linux", value: "linux" },
        { label: "Networking", value: "networking" },
        { label: "Tools", value: "tools" },
        { label: "Web Hacking", value: "web-hacking" },
        { label: "Windows", value: "windows" },
        { label: "Walkthroughs", value: "walkthroughs" },
      ],
    },

    {
      type: "string",
      name: "subcategories",
      label: "Sub Category",
      required: true,
      list: true,
      ui: {
        component: "select",
      },
      options: [
        { label: "Active Directory", value: "active-directory" },
        { label: "Comandi", value: "comandi" },
        { label: "Concetti", value: "concetti" },
        { label: "Critical", value: "critical" },
        { label: "Easy", value: "easy" },
        { label: "Enum", value: "enum" },
        { label: "Exploit", value: "expoit" },
        { label: "Filesystem", value: "filesystem" },
        { label: "Hard", value: "hard" },
        { label: "High", value: "high" },
        { label: "Low", value: "low" },
        { label: "Medium", value: "medium" },
        { label: "OWASP", value: "owasp" },
        { label: "Porte", value: "porte" },
        { label: "Post Exploit", value: "post-exploit" },
        { label: "Privilege Escalation", value: "privilege-escalation" },
        { label: "Protocolli", value: "protocolli" },
        { label: "Recon", value: "recon" },
        { label: "Risorse", value: "risorse" },
        { label: "Servizi", value: "servizi" },
        { label: "Tecniche", value: "tecniche" },
      ],
    },

    /* =====================
     * Tags (Still free text)
     * ===================== */

    {
      type: "string",
      name: "tags",
      label: "Tags",
      list: true,
      required: true,
    },

    {
      type: "boolean",
      name: "featured",
      label: "Featured",
    },

    /* =====================
     * Post Body
     * ===================== */

    {
      label: "Content",
      name: "body",
      isBody: true,
      type: "rich-text",
    },
  ],
};

export default Blog;