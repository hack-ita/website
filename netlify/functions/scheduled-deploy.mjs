// netlify/functions/scheduled-deploy.mjs

export default async (req) => {
  const { next_run } = await req.json();

  console.log("Scheduled deploy function triggered");
  console.log("Next scheduled run:", next_run);

  try {
    // Get the build hook URL from environment variable
    const buildHookUrl = process.env.NETLIFY_BUILD_HOOK;

    if (!buildHookUrl) {
      console.error("NETLIFY_BUILD_HOOK environment variable not set!");
      return new Response(
        JSON.stringify({ error: "Build hook URL not configured" }),
        { status: 500 },
      );
    }

    // Trigger the Netlify build
    const response = await fetch(buildHookUrl, {
      method: "POST",
      body: JSON.stringify({}),
    });

    if (response.ok) {
      console.log("Netlify build triggered successfully!");
      return new Response(
        JSON.stringify({
          success: true,
          message: "Build triggered",
          next_run,
        }),
        { status: 200 },
      );
    } else {
      console.error("❌ Failed to trigger build:", response.status);
      return new Response(
        JSON.stringify({ error: "Failed to trigger build" }),
        { status: 500 },
      );
    }
  } catch (error) {
    console.error("❌ Error triggering build:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
    });
  }
};

// Schedule: Runs at 01:00 UTC daily (02:00 CET/03:00 CEST Italy time)
// This is 2 hours after the GitHub Action runs at 23:00 UTC (00:00 Italy time)
export const config = {
  schedule: "0 1 * * *",
};
