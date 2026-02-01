// netlify/functions/scheduled-deploy.mjs

import { schedule } from "@netlify/functions";

// The actual handler function that will run on schedule
const scheduledHandler = async (event) => {
  const { next_run } = JSON.parse(event.body);

  console.log("🕐 Scheduled deploy triggered at:", new Date().toISOString());
  console.log("⏰ Next scheduled run:", next_run);

  try {
    // Get the build hook URL from environment variable
    const buildHookUrl = process.env.NETLIFY_BUILD_HOOKS;

    if (!buildHookUrl) {
      console.error("❌ NETLIFY_BUILD_HOOKS environment variable not set!");
      return {
        statusCode: 500,
        body: JSON.stringify({
          error: "Build hook URL not configured",
          timestamp: new Date().toISOString(),
        }),
      };
    }

    console.log("🚀 Triggering Netlify build...");

    // Trigger the Netlify build
    const response = await fetch(buildHookUrl, {
      method: "POST",
      body: JSON.stringify({
        trigger: "scheduled-function",
      }),
    });

    if (response.ok) {
      console.log("✅ Netlify build triggered successfully!");
      return {
        statusCode: 200,
        body: JSON.stringify({
          success: true,
          message: "Build triggered successfully",
          timestamp: new Date().toISOString(),
          next_run,
        }),
      };
    } else {
      const errorText = await response.text();
      console.error("❌ Failed to trigger build:", response.status, errorText);
      return {
        statusCode: 500,
        body: JSON.stringify({
          error: "Failed to trigger build",
          status: response.status,
          details: errorText,
        }),
      };
    }
  } catch (error) {
    console.error("❌ Error triggering build:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: error.message,
        stack: error.stack,
      }),
    };
  }
};

// Export the handler wrapped with the schedule function
// Runs at 01:00 UTC daily (02:00 CET/03:00 CEST Italy time)
// export const handler = schedule("0 1 * * *", scheduledHandler);
export const handler = schedule("30 14 * * *", scheduledHandler);