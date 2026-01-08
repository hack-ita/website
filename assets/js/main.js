"use strict";

/* ===========================
  GLOBAL DEBUG & LOGGING
=========================== */
const DEBUG = true;
const log = (...args) => DEBUG && console.log("LOG:", ...args);
const warn = (...args) => DEBUG && console.warn("WARN:", ...args);
const error = (...args) => console.error("ERROR:", ...args);

/* ===========================
  GLOBAL ERROR HANDLING
=========================== */
window.addEventListener("error", (e) =>
  error("GLOBAL ERROR:", e.message, e.filename, e.lineno)
);
window.addEventListener("unhandledrejection", (e) =>
  error("PROMISE ERROR:", e.reason)
);

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
  sideBar: true,
  search: true,
  filters: true,
  swiper: true,
  glightbox: true,
  newsletter: true,
};

/* ===========================
  PERFORMANCE HELPERS
=========================== */
const onIdle = (cb, timeout = 1500) => {
  if ("requestIdleCallback" in window) {
    requestIdleCallback(cb, { timeout });
  } else {
    setTimeout(cb, timeout);
  }
};

const onWindowLoad = (cb) => {
  if (document.readyState === "complete") cb();
  else window.addEventListener("load", cb, { once: true });
};

/* ===========================
  DOM READY (CRITICAL ONLY)
=========================== */
document.addEventListener("DOMContentLoaded", () => {
  const safeQuery = (s) => document.querySelector(s);
  const safeQueryAll = (s) => document.querySelectorAll(s);

  const safeExecute = (fn, name) => {
    try {
      fn();
    } catch (e) {
      error(`${name} crash:`, e);
    }
  };

  /* ===========================
    MENU (CRITICAL)
  =========================== */
  safeExecute(() => {
    if (!FEATURES.menu) return;
    const menuToggler = safeQuery(".menuToggler");
    const menu = safeQuery(".menu");
    if (!menuToggler || !menu) return;

    menuToggler.addEventListener("click", () => {
      menuToggler.classList.toggle("gap-y-3");
      menuToggler.children[0]?.classList.toggle("rotate-45");
      menuToggler.children[1]?.classList.toggle("-rotate-45");
      menu.classList.toggle("translate-y-10");
      menu.classList.toggle("pointer-events-none");
      menu.classList.toggle("opacity-0");
      document.body.classList.toggle("overflow-hidden");
    });
  }, "Menu");

  /* ===========================
    THEME (CRITICAL)
  =========================== */
  safeExecute(() => {
    const selector = safeQuery("#theme-selector");
    if (!selector) return;
    const html = document.documentElement;

    const applyTheme = (t) => {
      html.classList.remove("dark");
      if (t === "dark") html.classList.add("dark");
    };

    selector.value = "dark";
    applyTheme("dark");
    selector.addEventListener("change", (e) => applyTheme(e.target.value));
  }, "Theme");

  /* ===========================
    HEADER SCROLL (CRITICAL)
  =========================== */
  safeExecute(() => {
    if (!FEATURES.header) return;
    const header = safeQuery(".header");
    if (!header) return;

    const onScroll = () =>
      header.classList.toggle("header-glass", window.scrollY > 0);

    onScroll();
    window.addEventListener("scroll", () =>
      requestAnimationFrame(onScroll)
    );
  }, "Header");

  /* ===========================
    NON-CRITICAL UI (IDLE)
  =========================== */
  onIdle(() => {
    /* TYPEWRITER */
    safeExecute(() => {
      if (!FEATURES.typewriter) return;
      const data = safeQuery("#typewriter-data");
      const target = safeQuery("#typewriter");
      if (!data || !target) return;

      const words = [...data.children].map((s) => s.textContent.trim());
      let w = 0, c = 0, del = false, pause = false;
      const TYPE = 90, DEL = 50, HOLD = 2200, GAP = 400;

      const tick = () => {
        const word = words[w];
        let d = del ? DEL : TYPE;

        if (!del) {
          if (c < word.length) target.textContent = word.slice(0, ++c);
          else if (!pause) (pause = true), (d = HOLD);
          else (pause = false), (del = true);
        } else {
          if (c > 0) target.textContent = word.slice(0, --c);
          else (del = false), (w = (w + 1) % words.length), (d = GAP);
        }
        setTimeout(tick, d);
      };
      tick();
    }, "Typewriter");

    /* COUNTERS */
    safeExecute(() => {
      if (!FEATURES.counters) return;
      document.querySelectorAll(".card-spotlight span").forEach((span) => {
        const text = span.textContent.trim();
        const num = /^\d+/.test(text);
        span.textContent = num ? "0" : "";

        const obs = new IntersectionObserver(
          ([e]) => {
            if (!e.isIntersecting) return;
            obs.disconnect();

            if (num) {
              const target = parseInt(text, 10);
              const start = performance.now();
              const dur = 2000;
              const run = (t) => {
                const p = Math.min((t - start) / dur, 1);
                span.textContent = Math.floor(p * target);
                if (p < 1) requestAnimationFrame(run);
              };
              requestAnimationFrame(run);
            } else span.textContent = text;
          },
          { threshold: 0.6 }
        );
        obs.observe(span);
      });
    }, "Counters");

    /* BACK TO TOP */
    safeExecute(() => {
      if (!FEATURES.backToTop) return;
      const btn = safeQuery("#back-to-top");
      if (!btn) return;

      const update = () =>
        btn.classList.toggle("translate-y-70", window.scrollY < 300);

      window.addEventListener("scroll", () =>
        requestAnimationFrame(update)
      );
      btn.addEventListener("click", () =>
        window.scrollTo({ top: 0, behavior: "smooth" })
      );
      update();
    }, "BackToTop");

    /* READING PROGRESS */
    safeExecute(() => {
      if (!FEATURES.readingProgress) return;
      const bar = safeQuery("#reading-progress-bar");
      if (!bar) return;
      bar.style.transformOrigin = "left";

      const update = () => {
        const h =
          document.documentElement.scrollHeight - window.innerHeight;
        if (h <= 0) return;
        bar.style.transform = `scaleX(${window.scrollY / h})`;
      };
      window.addEventListener("scroll", () =>
        requestAnimationFrame(update)
      );
      update();
    }, "ReadingProgress");

    /* CODE COPY */
    safeExecute(() => {
      if (!FEATURES.codeCopy) return;
      document.querySelectorAll("pre > code").forEach((code) => {
        const pre = code.parentElement;
        if (!pre || pre.querySelector(".copy-btn")) return;
        const btn = document.createElement("button");
        btn.className = "copy-btn";
        btn.textContent = "Copy";
        btn.onclick = async () => {
          try {
            await navigator.clipboard.writeText(code.innerText);
            btn.textContent = "Copied!";
            setTimeout(() => (btn.textContent = "Copy"), 1500);
          } catch {
            btn.textContent = "Error";
          }
        };
        pre.style.position = "relative";
        pre.appendChild(btn);
      });
    }, "CodeCopy");
  });

  /* ===========================
    HEAVY / THIRD-PARTY (LOAD)
  =========================== */
  onWindowLoad(() => {
    /* ===========================
  SWIPER (HERO + ARTICLE)
=========================== */
    safeExecute(() => {
      if (!FEATURES.swiper || typeof Swiper === "undefined")
        return warn("Swiper skipped");

      /* ===========================
    HERO IMAGE SWIPER
  =========================== */
      const heroImgSwiper = new Swiper(".heroImgSwiper", {
        loop: true,
        spaceBetween: 10,
        pagination: {
          el: ".hero-swiper-pagination",
          clickable: true,
        },
        breakpoints: {
          1024: {
            allowTouchMove: false,
            noSwiping: true,
            pagination: { clickable: false },
          },
        },
      });

      let heroTextSwiper = null;
      let desktopAutoPlayInterval = null;
      const AUTOPLAY_DELAY = 5000;

      const clearDesktopAutoplay = () => {
        if (desktopAutoPlayInterval) {
          clearInterval(desktopAutoPlayInterval);
          desktopAutoPlayInterval = null;
        }
      };

      const setActiveSlide = (slides, index) => {
        slides.forEach((s) => s.classList.remove("swiper-slide-active"));
        slides[index]?.classList.add("swiper-slide-active");
        heroImgSwiper.slideToLoop(index);
      };

      /* ===========================
    DESKTOP MODE (CUSTOM LOGIC)
  =========================== */
      const setupDesktopHoverSync = () => {
        clearDesktopAutoplay();

        if (heroTextSwiper) {
          heroTextSwiper.destroy(true, true);
          heroTextSwiper = null;
        }

        const slides = document.querySelectorAll(
          ".heroTextSwiper .swiper-slide"
        );
        if (!slides.length) return;

        let index = 0;
        setActiveSlide(slides, index);

        slides.forEach((slide, i) => {
          slide.addEventListener("mouseenter", () => {
            index = i;
            setActiveSlide(slides, i);
          });
        });

        desktopAutoPlayInterval = setInterval(() => {
          index = (index + 1) % slides.length;
          setActiveSlide(slides, index);
        }, AUTOPLAY_DELAY);
      };

      /* ===========================
    MOBILE MODE
    - Image swipe controls text
    - Text swipe does NOTHING
  =========================== */
      const setupMobileSync = () => {
        clearDesktopAutoplay();

        if (heroTextSwiper) {
          heroTextSwiper.destroy(true, true);
        }

        heroTextSwiper = new Swiper(".heroTextSwiper", {
          loop: true,
          spaceBetween: 10,

          // 🔒 FULLY DISABLE USER INTERACTION
          allowTouchMove: false,
          simulateTouch: false,
          followFinger: false,
          shortSwipes: false,
          longSwipes: false,
          grabCursor: false,
          touchStartPreventDefault: true,
        });

        // ✅ ONE-WAY SYNC ONLY
        heroImgSwiper.controller.control = heroTextSwiper;
        heroTextSwiper.controller.control = null;
      };

      const setupResponsiveMode = () => {
        if (window.innerWidth >= 1024) {
          setupDesktopHoverSync();
        } else {
          setupMobileSync();
        }
      };

      window.addEventListener("resize", setupResponsiveMode);
      setupResponsiveMode();

      /* ===========================
    ARTICLE SWIPER
  =========================== */
      new Swiper(".articleSwiper", {
        loop: true,
        slidesPerView: 2,
        spaceBetween: 20,
        autoplay: true,
        navigation: {
          prevEl: ".prev-article",
          nextEl: ".next-article",
        },
        breakpoints: {
          1024: {
            slidesPerView: 4,
            autoplay: false,
          },
        },
      });

      log("Swiper (hero + article) initialized");
    }, "Swiper");

    /* GLIGHTBOX */
    safeExecute(() => {
      if (!FEATURES.glightbox || typeof GLightbox === "undefined") return;
      GLightbox({ selector: ".glightbox" });
    }, "Lightbox");

    /* SEARCH (PAGEFIND – LAZY LOAD ON INPUT) */
    safeExecute(() => {
      if (!FEATURES.search) return;
      const input = safeQuery("#search-input");
      const list = safeQuery("#search-suggestions");
      if (!input || !list) return;

      let pagefind = null;
      let loading = false;

      const loadPagefind = async () => {
        if (pagefind || loading) return;
        loading = true;
        pagefind = await import("/pagefind/pagefind.js");
        await pagefind.options({ bundlePath: "/pagefind/" });
        pagefind.init();
      };

      input.addEventListener("input", async (e) => {
        const q = e.target.value.trim();
        if (!q) return (list.innerHTML = "");
        await loadPagefind();
        const res = await pagefind.search(q);
        list.innerHTML = res.results
          .slice(0, 6)
          .map((r) => `<li><a href="${r.url}">${r.url}</a></li>`)
          .join("");
      });
    }, "Search");

    /* NEWSLETTER */
    safeExecute(() => {
      if (!FEATURES.newsletter) return;
      const form = document.querySelector(".hn-form");
      if (!form) return;
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = form.querySelector("input")?.value;
        if (!email) return;
        await fetch("/.netlify/functions/subscribe", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        });
        form.reset();
      });
    }, "Newsletter");
  });
});