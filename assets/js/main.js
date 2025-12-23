"use strict";

/* ===========================
  GLOBAL DEBUG & LOGGING
=========================== */
const DEBUG = false; // Set FALSE in production
const log = (...args) => DEBUG && console.log("LOG:", ...args);
const warn = (...args) => DEBUG && console.warn("WARN:", ...args);
const error = (...args) => console.error("ERROR:", ...args);

/* ===========================
  GLOBAL ERROR HANDLING
=========================== */
window.addEventListener("error", (e) => error("GLOBAL ERROR:", e.message, e.filename, e.lineno));
window.addEventListener("unhandledrejection", (e) => error("PROMISE ERROR:", e.reason));

/* ===========================
  FEATURE TOGGLES
=========================== */
const FEATURES = {
  menu: true,
  header: true,
  typewriter: true,
  grid: false,
  counters: true,
  codeCopy: true,
  backToTop: true,
  readingProgress: true,
  search: true,
  swiper: true,
  glightbox: true,
  newsletter: true
};

/* ===========================
  DOM READY
=========================== */
document.addEventListener("DOMContentLoaded", () => {
  log("DOM fully loaded");

  // SAFE SELECTORS
  const safeQuery = (sel) => document.querySelector(sel);
  const safeQueryAll = (sel) => document.querySelectorAll(sel);

  const menuToggler = safeQuery(".menuToggler");
  const menu = safeQuery(".menu");
  const header = safeQuery(".header");
  const headerBar = safeQuery(".headerBar");
  const headerLogo = safeQuery(".headerLogo");
  const grid = safeQuery("#stats-grid");
  const cards = safeQueryAll(".card-spotlight");
  const counters = safeQueryAll(".card-spotlight span");

  // ===========================
  // UTILITY WRAPPER
  // ===========================
  const safeExecute = (fn, name) => {
    try {
      fn();
    } catch (e) {
      error(`${name} crash:`, e);
    }
  };

  // ===========================
  // MENU TOGGLE
  // ===========================
  safeExecute(() => {
    if (!FEATURES.menu || !menuToggler || !menu) return warn("Menu skipped");
    log("Menu initialized");
    menuToggler.addEventListener("click", () => {
      menuToggler.classList.toggle("gap-y-3");
      menuToggler.children[0]?.classList.toggle("rotate-45");
      menuToggler.children[1]?.classList.toggle("-rotate-45");
      menu.classList.toggle("translate-y-10");
      menu.classList.toggle("pointer-events-none");
      menu.classList.toggle("opacity-0");
      document.body.classList.toggle("overflow-hidden");
      log("Menu toggled");
    });
  }, "Menu");

  // ===========================
  // THEME DROPDOWN: DARK / LIGHT (NO PERSISTENCE)
  // ===========================
  safeExecute(() => {
    const selector = safeQuery("#theme-selector");
    if (!selector) return warn("Theme selector not found");

    const html = document.documentElement;

    const applyTheme = (theme) => {
      html.classList.remove("dark");

      if (theme === "dark") {
        html.classList.add("dark");
        log("Theme set to dark");
      } else {
        log("Theme set to light");
      }
    };

    // Always start in dark mode
    selector.value = "dark";
    applyTheme("dark");

    selector.addEventListener("change", (e) => {
      applyTheme(e.target.value);
    });
  }, "ThemeToggle");

  // ===========================
  // HEADER SCROLL EFFECT
  // ===========================
  safeExecute(() => {
    if (!FEATURES.header || !header || !headerBar)
      return warn("Header scroll skipped");
    log("Header scroll effect enabled");
    const handleScroll = () => {
      const scrolled = window.scrollY > 0;
      header.classList.toggle("header-glass", scrolled);
      headerBar.classList.toggle("py-3", !scrolled);
      headerBar.classList.toggle("py-1", scrolled);
    };
    handleScroll();
    window.addEventListener("scroll", () =>
      requestAnimationFrame(handleScroll)
    );
  }, "Header");

  // ===========================
  // TYPEWRITER EFFECT
  // ===========================
  safeExecute(() => {
    if (!FEATURES.typewriter) return warn("Typewriter feature disabled");
    const dataContainer = safeQuery("#typewriter-data");
    const target = safeQuery("#typewriter");
    if (!dataContainer || !target)
      return warn("Typewriter skipped (missing elements)");
    log("Typewriter initialized");

    const words = Array.from(dataContainer.children).map((s) =>
      s.textContent.trim()
    );
    if (!words.length) return warn("Typewriter skipped (no words found)");

    let wordIndex = 0,
      charIndex = 0,
      isDeleting = false,
      pendingPause = false;
    const TYPING_SPEED = 90,
      DELETING_SPEED = 50,
      HOLD_AFTER_TYPE = 2200,
      HOLD_AFTER_DELETE = 400;

    const typeEffect = () => {
      const word = words[wordIndex];
      let delay = isDeleting ? DELETING_SPEED : TYPING_SPEED;
      if (!isDeleting) {
        if (charIndex < word.length)
          target.textContent = word.substring(0, ++charIndex);
        else {
          if (!pendingPause) {
            pendingPause = true;
            delay = HOLD_AFTER_TYPE;
          } else {
            pendingPause = false;
            isDeleting = true;
          }
        }
      } else {
        if (charIndex > 0) target.textContent = word.substring(0, --charIndex);
        else {
          isDeleting = false;
          wordIndex = (wordIndex + 1) % words.length;
          delay = HOLD_AFTER_DELETE;
        }
      }
      setTimeout(typeEffect, delay);
    };
    typeEffect();
  }, "Typewriter");

  // ===========================
  // GRID HOVER EFFECT
  // ===========================
  safeExecute(() => {
    if (!FEATURES.grid || !grid || !cards.length)
      return warn("Grid hover skipped");
    log("Grid hover enabled");
    grid.addEventListener("mousemove", (e) => {
      const gx = e.clientX,
        gy = e.clientY;
      cards.forEach((card) => {
        const rect = card.getBoundingClientRect();
        const x = Math.min(Math.max(gx - rect.left, 0), rect.width);
        const y = Math.min(Math.max(gy - rect.top, 0), rect.height);
        card.style.setProperty("--x", `${x}px`);
        card.style.setProperty("--y", `${y}px`);
        card.style.setProperty("--o", `1`);
      });
    });
    grid.addEventListener("mouseleave", () => {
      cards.forEach((c) => c.style.setProperty("--o", "0"));
    });
  }, "Grid");

  // ===========================
  // COUNTERS
  // ===========================
  safeExecute(() => {
    if (!FEATURES.counters || !counters.length) return warn("Counters skipped");
    log("Counters initialized");

    counters.forEach((span) => {
      const finalText = span.textContent.trim();
      const isNumber = /^[0-9]+$/.test(finalText);
      const duration = 2000,
        delay = 800;
      let started = false;
      span.textContent = isNumber ? "0" : "";

      const animate = () => {
        if (started) return;
        started = true;

        if (isNumber) {
          const match = finalText.match(/^(\d+)(.*)$/);
          if (!match) return;
          const target = parseInt(match[1], 10),
            suffix = match[2] || "";
          const startTime = performance.now();
          const update = (time) => {
            const progress = Math.min((time - startTime) / duration, 1);
            span.textContent = Math.floor(progress * target) + suffix;
            if (progress < 1) requestAnimationFrame(update);
            else span.textContent = finalText;
          };
          setTimeout(() => requestAnimationFrame(update), delay);
        } else {
          const chars = "!<>-_\\/[]{}—=+*^?#________";
          let frame = 0;
          const scramble = () => {
            span.textContent = finalText
              .split("")
              .map((char, i) =>
                i < frame
                  ? finalText[i]
                  : chars[Math.floor(Math.random() * chars.length)]
              )
              .join("");
            frame++;
            if (frame <= finalText.length) setTimeout(scramble, 30);
            else span.textContent = finalText;
          };
          setTimeout(scramble, delay);
        }
      };

      const observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) animate();
          });
        },
        { threshold: 0.6 }
      );
      observer.observe(span);
    });
  }, "Counters");

  // ===========================
  // CODE BLOCK COPY BUTTON
  // ===========================
  safeExecute(() => {
    if (!FEATURES.codeCopy) return warn("Code copy feature disabled");

    const codeBlocks = document.querySelectorAll("pre > code");

    if (!codeBlocks.length) {
      return warn("No code blocks found for copy button");
    }

    log(`Initializing copy buttons for ${codeBlocks.length} code blocks`);

    codeBlocks.forEach((codeBlock, index) => {
      const pre = codeBlock.parentElement;
      if (!pre) return;

      // Prevent duplicate buttons (important for client-side nav / hot reload)
      if (pre.querySelector(".copy-btn")) return;

      pre.style.position = "relative";

      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy-btn";
      button.textContent = "Copy";

      button.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(codeBlock.innerText);
          button.textContent = "Copied!";
          log(`Code block ${index + 1} copied`);

          setTimeout(() => {
            button.textContent = "Copy";
          }, 1500);
        } catch (e) {
          error("Clipboard copy failed:", e);
          button.textContent = "Error";
          setTimeout(() => (button.textContent = "Copy"), 1500);
        }
      });

      pre.appendChild(button);
    });
  }, "CodeCopy");

  // ===========================
  // BACK TO TOP BUTTON
  // ===========================
  safeExecute(() => {
    if (!FEATURES.backToTop) return warn("Back-to-top feature disabled");

    const btn = safeQuery("#back-to-top");
    if (!btn) return warn("Back-to-top skipped (button not found)");

    log("Back-to-top initialized");

    const VISIBILITY_OFFSET = 300;

    const updateVisibility = () => {
      const visible = window.scrollY > VISIBILITY_OFFSET;
      btn.classList.toggle("translate-y-70", !visible);
    };

    window.addEventListener("scroll", () =>
      requestAnimationFrame(updateVisibility)
    );

    btn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
      log("Back-to-top clicked");
    });

    updateVisibility();
  }, "BackToTop");

  // ===========================
  // READING PROGRESS BAR
  // ===========================
  safeExecute(() => {
    if (!FEATURES.readingProgress)
      return warn("Reading progress feature disabled");

    const progressRoot = safeQuery("#reading-progress");
    const progressBar = safeQuery("#reading-progress-bar");

    if (!progressRoot || !progressBar) {
      return warn("Reading progress skipped (elements not found)");
    }

    log("Reading progress initialized");

    const updateProgress = () => {
      const scrollTop = window.scrollY;
      const docHeight =
        document.documentElement.scrollHeight - window.innerHeight;

      if (docHeight <= 0) return;

      const progress = Math.min(scrollTop / docHeight, 1);
      progressBar.style.transform = `scaleX(${progress})`;
    };

    // Use transform for better performance
    progressBar.style.transformOrigin = "left";
    progressBar.style.transform = "scaleX(0)";

    window.addEventListener("scroll", () =>
      requestAnimationFrame(updateProgress)
    );

    updateProgress();
  }, "ReadingProgress");

  // ===========================
  // SEARCH
  // ===========================
  safeExecute(() => {
    if (!FEATURES.search) return warn("Search feature disabled");

    const input = safeQuery("#search-input");
    const suggList = safeQuery("#search-suggestions");
    const previewRoot = safeQuery("#preview-root");

    if (!input || !suggList || !previewRoot) {
      return warn("Search skipped (missing elements)");
    }

    log("Search initialized");

    // ---------------------------
    // PREVIEW CARD
    // ---------------------------
    const preview = document.createElement("div");
    preview.className = "link-preview";
    preview.style.display = "none";
    previewRoot.appendChild(preview);

    let pagefind = null;
    let timer = null;

    // ---------------------------
    // SEARCH STATES (NO INITIAL STATE)
    // ---------------------------
    const STATES = {
      loading: "Searching…",
      empty: "No results found",
      error: "Search failed. Try again.",
    };

    const showResults = () => {
      suggList.style.display = "block";
    };

    const hideResults = () => {
      suggList.innerHTML = "";
      suggList.style.display = "none";
      preview.style.display = "none";
    };

    const setState = (state) => {
      showResults();
      suggList.innerHTML = `
      <li class="search-state" data-state="${state}">
        ${STATES[state] || ""}
      </li>
    `;
    };

    // Start hidden (initial page state)
    hideResults();

    // ---------------------------
    // INIT PAGEFIND
    // ---------------------------
    const initPagefind = async () => {
      try {
        pagefind = await import("/pagefind/pagefind.js");
        await pagefind.options({
          baseUrl: "/",
          bundlePath: "/pagefind/",
          excerptLength: 25,
          highlightParam: "highlight",
        });
        pagefind.init();
        log("Pagefind ready");
      } catch (e) {
        error("Pagefind init failed:", e);
      }
    };
    initPagefind();

    // ---------------------------
    // INPUT HANDLER (DEBOUNCED)
    // ---------------------------
    input.addEventListener("input", (e) => {
      clearTimeout(timer);

      const term = e.target.value.trim();

      // Empty input → fully reset to initial invisible state
      if (!term) {
        hideResults();
        return;
      }

      setState("loading");

      timer = setTimeout(async () => {
        if (!pagefind) {
          warn("Search attempted before Pagefind ready");
          setState("error");
          return;
        }

        try {
          const res = await pagefind.search(term);

          if (!res.results.length) {
            setState("empty");
            return;
          }

          suggList.innerHTML = "";
          showResults();

          res.results.slice(0, 8).forEach(async (hit) => {
            try {
              const data = await hit.data();
              const li = document.createElement("li");

              li.innerHTML = `
              <a href="${data.url}">
                <strong>${data.meta?.title || data.url}</strong>
                <p>${data.excerpt || ""}</p>
              </a>
            `;

              suggList.appendChild(li);
            } catch (e) {
              warn("Search result render failed:", e);
            }
          });
        } catch (e) {
          error("Search failed:", e);
          setState("error");
        }
      }, 200);
    });

    // ---------------------------
    // HOVER PREVIEW
    // ---------------------------
    suggList.addEventListener("mouseover", (e) => {
      const item = e.target.closest("li");
      if (!item || item.classList.contains("search-state")) return;

      const a = item.querySelector("a");
      if (!a) return;

      const title = a.querySelector("strong")?.textContent || "";
      const desc = a.querySelector("p")?.textContent || "";
      const url = a.href;

      preview.innerHTML = `
      <h4>${title}</h4>
      <p>${desc}</p>
      <small>${url}</small>
    `;

      preview.style.display = "block";
      preview.style.left = `${e.pageX + 12}px`;
      preview.style.top = `${e.pageY + 6}px`;
    });

    suggList.addEventListener("mouseleave", () => {
      preview.style.display = "none";
    });
  }, "Search");

  // ===========================
  // PLUGINS: SWIPER
  // ===========================
  safeExecute(() => {
    if (!FEATURES.swiper || typeof Swiper === "undefined")
      return warn("Swiper skipped");
    log("Swiper initialization started");

    // HERO IMAGE SWIPER
    const heroImgSwiper = new Swiper(".heroImgSwiper", {
      loop: true,
      spaceBetween: 10,
      pagination: { el: ".hero-swiper-pagination", clickable: true },
      breakpoints: {
        1024: {
          allowTouchMove: false,
          noSwiping: true,
          pagination: { clickable: false },
        },
      },
    });

    // HERO TEXT SWIPER
    let heroTextSwiper = new Swiper(".heroTextSwiper", {
      loop: true,
      spaceBetween: 10,
      noSwiping: true,
      allowTouchMove: false,
      breakpoints: {
        1024: {
          direction: "vertical",
          slidesPerView: 3,
          allowTouchMove: true,
          noSwiping: false,
        },
      },
    });

    const AUTOPLAY_DELAY = 5000;
    let desktopAutoPlayInterval = null;

    const clearDesktopAutoplay = () => {
      if (desktopAutoPlayInterval) {
        clearInterval(desktopAutoPlayInterval);
        desktopAutoPlayInterval = null;
      }
    };
    const setActiveSlide = (slides, index) => {
      slides.forEach((s) => s.classList.remove("swiper-slide-active"));
      slides[index].classList.add("swiper-slide-active");
      heroImgSwiper.slideToLoop(index);
    };

    const setupDesktopHoverSync = () => {
      heroTextSwiper.destroy();
      clearDesktopAutoplay();
      const slides = safeQueryAll(".heroTextSwiper .swiper-slide");
      if (!slides.length) return;
      setActiveSlide(slides, 0);
      slides.forEach((slide, i) =>
        slide.addEventListener("mouseenter", () => setActiveSlide(slides, i))
      );
      let idx = 0;
      desktopAutoPlayInterval = setInterval(() => {
        idx = (idx + 1) % slides.length;
        setActiveSlide(slides, idx);
      }, AUTOPLAY_DELAY);
    };

    const setupMobileSync = () => {
      clearDesktopAutoplay();
      heroImgSwiper.controller.control = heroTextSwiper;
    };
    const setupHoverSync = () => {
      window.innerWidth >= 1024 ? setupDesktopHoverSync() : setupMobileSync();
    };

    window.addEventListener("resize", setupHoverSync);
    setupHoverSync();

    // ARTICLE SWIPER
    new Swiper(".articleSwiper", {
      loop: true,
      slidesPerView: 2,
      spaceBetween: 20,
      autoplay: true,
      navigation: { prevEl: ".prev-article", nextEl: ".next-article" },
      breakpoints: { 1024: { slidesPerView: 4, autoplay: false } },
    });

    log("Swiper initialized");
  }, "Plugins");

  // ===========================
  // IMAGE LIGHTBOX
  // ===========================
  safeExecute(() => {
    if (!FEATURES.glightbox || typeof GLightbox === "undefined")
      return warn("GLightbox skipped");

    const selector = ".glightbox";
    const items = document.querySelectorAll(selector);

    if (!items.length) return warn("Lightbox skipped (no images found)");

    log(`Initializing lightbox for ${items.length} images`);

    GLightbox({
      selector,
      zoomable: true,
      draggable: true,
      touchNavigation: true,
      keyboardNavigation: true,
      closeButton: true,
      loop: false,
      openEffect: "zoom",
      closeEffect: "fade",
      slideEffect: "slide",
      moreLength: 0,
      download: true,
    });
  }, "Lightbox");

  // ===========================
  // NEWSLETTER SUBSCRIPTION
  // ===========================
  safeExecute(() => {
    if (!FEATURES.newsletter) return warn("Newsletter feature disabled");

    const form = safeQuery(".hn-form");
    if (!form) return warn("Newsletter skipped (form not found)");

    const emailInput = safeQuery("#newsletter-email");
    const button = form.querySelector("button");

    if (!emailInput || !button) {
      return warn("Newsletter skipped (missing input or button)");
    }

    log("Newsletter subscription initialized");

    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const email = emailInput.value.trim();
      if (!email) {
        warn("Newsletter submit blocked (empty email)");
        return;
      }

      button.disabled = true;
      log("Newsletter submit started", email);

      try {
        const res = await fetch("/.netlify/functions/subscribe", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        });

        if (res.ok) {
          form.reset();
          log("Newsletter subscription success");
          alert("🎉 Sei iscritto alla newsletter!");
        } else {
          warn("Newsletter subscription failed", res.status);
          alert("❌ Errore durante l’iscrizione.");
        }
      } catch (e) {
        error("Newsletter request failed:", e);
        alert("❌ Connessione fallita.");
      } finally {
        button.disabled = false;
        log("Newsletter submit finished");
      }
    });
  }, "Newsletter");
});