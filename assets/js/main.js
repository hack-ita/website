"use strict";

/* ===========================
  OPTIMIZED FOR PRODUCTION
  - Reduced main thread blocking
  - Deferred non-critical features
  - Improved LCP/FCP metrics
=========================== */

const DEBUG = false;
const log = (...args) => DEBUG && console.log("LOG:", ...args);
const warn = (...args) => DEBUG && console.warn("WARN:", ...args);
const error = (...args) => console.error("ERROR:", ...args);

// Global error handling (passive)
window.addEventListener(
  "error",
  (e) => error("GLOBAL ERROR:", e.message, e.filename, e.lineno),
  { passive: true }
);
window.addEventListener(
  "unhandledrejection",
  (e) => error("PROMISE ERROR:", e.reason),
  { passive: true }
);

/* ===========================
  FEATURE PRIORITIES
  Critical = Load immediately (affects UX)
  Deferred = Load after paint (visual enhancements)
=========================== */
const FEATURES = {
  // CRITICAL (blocking)
  menu: true,
  header: true,
  themeToggle: true,
  captcha: true,

  // DEFERRED (non-blocking)
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
  faq: true,
};

// Cache DOM queries
const DOM = {};
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => ctx.querySelectorAll(sel);

// Safe execution wrapper
const safe = (fn, name) => {
  try {
    fn();
  } catch (e) {
    error(`${name} error:`, e);
  }
};

// Defer execution until idle
const defer = (fn, timeout = 100) => {
  if ("requestIdleCallback" in window) {
    requestIdleCallback(fn, { timeout });
  } else {
    setTimeout(fn, timeout);
  }
};

/* ===========================
  CRITICAL PATH - LOAD IMMEDIATELY
=========================== */
const initCritical = () => {
  // Cache critical elements
  DOM.menuToggler = $(".menuToggler");
  DOM.menu = $(".menu");
  DOM.header = $(".header");
  DOM.headerBar = $(".headerBar");

  // MENU TOGGLE
  if (FEATURES.menu && DOM.menuToggler && DOM.menu) {
    DOM.menuToggler.addEventListener(
      "click",
      () => {
        DOM.menuToggler.classList.toggle("gap-y-3");
        DOM.menuToggler.children[0]?.classList.toggle("rotate-45");
        DOM.menuToggler.children[1]?.classList.toggle("-rotate-45");
        DOM.menu.classList.toggle("translate-y-10");
        DOM.menu.classList.toggle("pointer-events-none");
        DOM.menu.classList.toggle("opacity-0");
        document.body.classList.toggle("overflow-hidden");
      },
      { passive: true }
    );
    log("Menu initialized");
  }

  // THEME TOGGLE
  safe(() => {
    const selector = $("#theme-selector");
    if (!selector) return;

    const html = document.documentElement;
    const STORAGE_KEY = "theme";

    const applyTheme = (theme) => {
      html.classList.toggle("dark", theme === "dark");
      sessionStorage.setItem(STORAGE_KEY, theme);
    };

    const savedTheme = sessionStorage.getItem(STORAGE_KEY) || "dark";

    applyTheme(savedTheme);
    selector.value = savedTheme;

    selector.addEventListener("change", (e) => applyTheme(e.target.value), {
      passive: true,
    });
  }, "Theme");

  // HEADER SCROLL (throttled)
  if (FEATURES.header && DOM.header && DOM.headerBar) {
    let ticking = false;
    const handleScroll = () => {
      DOM.header.classList.toggle("header-glass", window.scrollY > 0);
      ticking = false;
    };

    handleScroll();
    window.addEventListener(
      "scroll",
      () => {
        if (!ticking) {
          requestAnimationFrame(handleScroll);
          ticking = true;
        }
      },
      { passive: true }
    );
    log("Header scroll enabled");
  }

  // CAPTCHA INITIALIZATION
  if (FEATURES.captcha) {
    safe(() => {
      const forms = $$('[data-captcha-form]');
      
      if (!forms.length) return;

      forms.forEach(form => {
        const captchaBox = form.querySelector('.captcha-container');
        const checkbox = form.querySelector('.checkbox-wrapper');
        const spinner = form.querySelector('.spinner');
        const checkmark = form.querySelector('.checkmark');
        const captchaWrapper = form.querySelector('.captcha-wrapper');
        const submitButton = form.querySelector('.submit-btn');
        
        if (!captchaBox || !checkbox || !spinner || !checkmark || !captchaWrapper || !submitButton) {
          warn('Captcha: Missing required elements in form');
          return;
        }

        let captchaVerified = false;
        
        // Captcha click handler
        captchaBox.addEventListener('click', function(e) {
          if (captchaVerified) return;
          
          // Disable further clicks
          this.style.pointerEvents = 'none';
          
          // Show checking state
          checkbox.classList.add('checking');
          spinner.classList.add('show');
          
          // Simulate verification process (1.5-2.5 seconds)
          const verificationTime = 1500 + Math.random() * 1000;
          
          setTimeout(() => {
            // Hide spinner
            spinner.classList.remove('show');
            
            // Show success state
            checkbox.classList.remove('checking');
            checkbox.classList.add('verified');
            checkmark.classList.add('show');
            
            captchaVerified = true;
            
            // After a short delay, fade out captcha and show button
            setTimeout(() => {
              captchaWrapper.classList.add('captcha-fade-out');
              
              setTimeout(() => {
                captchaWrapper.style.display = 'none';
                submitButton.style.display = 'inline-flex';
                submitButton.classList.remove('hidden');
                submitButton.classList.add('button-enter');
              }, 400);
            }, 800);
          }, verificationTime);
        }, { passive: true });
      });

      log(`Captcha initialized (${forms.length} forms)`);
    }, "Captcha");
  }
};

/* ===========================
  DEFERRED FEATURES - LOAD AFTER PAINT
=========================== */
const initDeferred = () => {
  // TYPEWRITER EFFECT
  defer(
    () =>
      safe(() => {
        if (!FEATURES.typewriter) return;

        const dataContainer = $("#typewriter-data");
        const target = $("#typewriter");
        if (!dataContainer || !target) return;

        const words = Array.from(dataContainer.children)
          .map((s) => s.textContent.trim())
          .filter(Boolean);
        if (!words.length) return;

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
            if (charIndex < word.length) {
              target.textContent = word.substring(0, ++charIndex);
            } else {
              if (!pendingPause) {
                pendingPause = true;
                delay = HOLD_AFTER_TYPE;
              } else {
                pendingPause = false;
                isDeleting = true;
              }
            }
          } else {
            if (charIndex > 0) {
              target.textContent = word.substring(0, --charIndex);
            } else {
              isDeleting = false;
              wordIndex = (wordIndex + 1) % words.length;
              delay = HOLD_AFTER_DELETE;
            }
          }
          setTimeout(typeEffect, delay);
        };
        typeEffect();
        log("Typewriter initialized");
      }, "Typewriter"),
    200,
  );

  // GRID HOVER EFFECT
  defer(
    () =>
      safe(() => {
        if (!FEATURES.grid) return;

        const grid = $("#stats-grid");
        const cards = $$(".card-spotlight");
        if (!grid || !cards.length) return;

        let rafId = null;
        grid.addEventListener(
          "mousemove",
          (e) => {
            if (rafId) return;
            rafId = requestAnimationFrame(() => {
              const gx = e.clientX,
                gy = e.clientY;
              cards.forEach((card) => {
                const rect = card.getBoundingClientRect();
                const x = Math.min(Math.max(gx - rect.left, 0), rect.width);
                const y = Math.min(Math.max(gy - rect.top, 0), rect.height);
                card.style.setProperty("--x", `${x}px`);
                card.style.setProperty("--y", `${y}px`);
                card.style.setProperty("--o", "1");
              });
              rafId = null;
            });
          },
          { passive: true },
        );

        grid.addEventListener(
          "mouseleave",
          () => {
            cards.forEach((c) => c.style.setProperty("--o", "0"));
          },
          { passive: true },
        );
        log("Grid hover enabled");
      }, "Grid"),
    300,
  );

  // COUNTERS (IntersectionObserver)
  defer(
    () =>
      safe(() => {
        if (!FEATURES.counters) return;

        const counters = $$(".card-spotlight span");
        if (!counters.length) return;

        const observer = new IntersectionObserver(
          (entries) => {
            entries.forEach((entry) => {
              if (!entry.isIntersecting) return;

              const span = entry.target;
              if (span.dataset.animated) return;
              span.dataset.animated = "true";

              const finalText = span.textContent.trim();
              const isNumber = /^[0-9]+$/.test(finalText);
              const duration = 2000;

              if (isNumber) {
                const match = finalText.match(/^(\d+)(.*)$/);
                if (!match) return;
                const target = parseInt(match[1], 10),
                  suffix = match[2] || "";
                span.textContent = "0";

                const startTime = performance.now();
                const update = (time) => {
                  const progress = Math.min((time - startTime) / duration, 1);
                  span.textContent = Math.floor(progress * target) + suffix;
                  if (progress < 1) requestAnimationFrame(update);
                  else span.textContent = finalText;
                };
                setTimeout(() => requestAnimationFrame(update), 800);
              } else {
                const chars = "!<>-_\\/[]{}—=+*^?#________";
                let frame = 0;
                span.textContent = "";

                const scramble = () => {
                  span.textContent = finalText
                    .split("")
                    .map((char, i) =>
                      i < frame
                        ? finalText[i]
                        : chars[Math.floor(Math.random() * chars.length)],
                    )
                    .join("");
                  frame++;
                  if (frame <= finalText.length) setTimeout(scramble, 30);
                  else span.textContent = finalText;
                };
                setTimeout(scramble, 800);
              }
            });
          },
          { threshold: 0.6, rootMargin: "50px" },
        );

        counters.forEach((span) => observer.observe(span));
        log("Counters initialized");
      }, "Counters"),
    400,
  );

  // CODE COPY BUTTONS
  defer(
    () =>
      safe(() => {
        if (!FEATURES.codeCopy) return;

        const codeBlocks = $$("pre > code");
        if (!codeBlocks.length) return;

        codeBlocks.forEach((codeBlock, index) => {
          const pre = codeBlock.parentElement;
          if (!pre || pre.querySelector(".copy-btn")) return;

          pre.style.position = "relative";
          pre.style.overflow = "auto";

          const button = document.createElement("button");
          button.type = "button";
          button.className = "copy-btn";
          button.textContent = "Copy";

          // Position button relative to pre element
          const updateButtonPosition = () => {
            const rect = pre.getBoundingClientRect();
            button.style.top = `${rect.top + 8}px`; // 8px = top-2
            button.style.left = `${rect.right - button.offsetWidth - 8}px`; // 8px from right
          };

          pre.insertBefore(button, pre.firstChild);
          updateButtonPosition();

          // Update position on scroll
          let scrollTimeout;
          const handleScroll = () => {
            button.style.opacity = "0.3";
            clearTimeout(scrollTimeout);
            updateButtonPosition();
            scrollTimeout = setTimeout(() => {
              button.style.opacity = "0.7";
            }, 150);
          };

          window.addEventListener("scroll", updateButtonPosition);
          window.addEventListener("resize", updateButtonPosition);
          pre.addEventListener("scroll", handleScroll);

          button.addEventListener("click", async () => {
            try {
              await navigator.clipboard.writeText(codeBlock.innerText);
              button.textContent = "Copied!";
              setTimeout(() => (button.textContent = "Copy"), 1500);
            } catch (e) {
              error("Copy failed:", e);
              button.textContent = "Error";
              setTimeout(() => (button.textContent = "Copy"), 1500);
            }
          });
        });
        log("Code copy initialized");
      }, "CodeCopy"),
    500,
  );

  // BACK TO TOP BUTTON
  defer(
    () =>
      safe(() => {
        if (!FEATURES.backToTop) return;

        const btn = $("#back-to-top");
        if (!btn) return;

        let ticking = false;
        const updateVisibility = () => {
          btn.classList.toggle("translate-y-70", window.scrollY <= 300);
          ticking = false;
        };

        window.addEventListener(
          "scroll",
          () => {
            if (!ticking) {
              requestAnimationFrame(updateVisibility);
              ticking = true;
            }
          },
          { passive: true },
        );

        btn.addEventListener("click", () =>
          window.scrollTo({ top: 0, behavior: "smooth" }),
        );
        updateVisibility();
        log("Back-to-top initialized");
      }, "BackToTop"),
    600,
  );

  // READING PROGRESS BAR
  defer(
    () =>
      safe(() => {
        if (!FEATURES.readingProgress) return;

        const progressBar = $("#reading-progress-bar");
        if (!progressBar) return;

        progressBar.style.transformOrigin = "left";
        progressBar.style.transform = "scaleX(0)";

        let ticking = false;
        const updateProgress = () => {
          const docHeight =
            document.documentElement.scrollHeight - window.innerHeight;
          if (docHeight > 0) {
            const progress = Math.min(window.scrollY / docHeight, 1);
            progressBar.style.transform = `scaleX(${progress})`;
          }
          ticking = false;
        };

        window.addEventListener(
          "scroll",
          () => {
            if (!ticking) {
              requestAnimationFrame(updateProgress);
              ticking = true;
            }
          },
          { passive: true },
        );

        updateProgress();
        log("Reading progress initialized");
      }, "ReadingProgress"),
    700,
  );

  // SIDEBAR TOGGLER
  defer(
    () =>
      safe(() => {
        if (!FEATURES.sideBar) return;

        const toggler = $(".sideBarToggler");
        const sideBar = $(".sideBar");
        if (!toggler || !sideBar) return;

        function openSidebar() {
          sideBar.classList.remove("translate-x-[100vw]");
          document.body.classList.add("overflow-hidden");
        }

        function closeSidebar() {
          sideBar.classList.add("translate-x-[100vw]");
          document.body.classList.remove("overflow-hidden");
        }

        toggler.addEventListener("click", () => {
          if (sideBar.classList.contains("translate-x-[100vw]")) {
            openSidebar();
          } else {
            closeSidebar();
          }
        });
        sideBar.addEventListener("click", () => closeSidebar());
        log("Sidebar initialized");
      }, "Sidebar"),
    800,
  );

  // SEARCH (lazy load Pagefind)
  defer(
    () =>
      safe(() => {
        if (!FEATURES.search) return;

        const input = $("#search-input");
        const suggList = $("#search-suggestions");
        const previewRoot = $("#preview-root");
        if (!input || !suggList || !previewRoot) return;

        const preview = document.createElement("div");
        preview.className = "link-preview";
        preview.style.display = "none";
        previewRoot.appendChild(preview);

        let pagefind = null;
        let timer = null;

        const STATES = {
          loading: "Searching…",
          empty: "No results found",
          error: "Search failed. Try again.",
        };

        const showResults = () => (suggList.style.display = "block");
        const hideResults = () => {
          suggList.innerHTML = "";
          suggList.style.display = "none";
          preview.style.display = "none";
        };
        const setState = (state) => {
          showResults();
          suggList.innerHTML = `<li class="search-state" data-state="${state}">${STATES[state]}</li>`;
        };

        hideResults();

        // Lazy load Pagefind on first interaction
        let pagefindLoaded = false;
        const initPagefind = async () => {
          if (pagefindLoaded) return;
          pagefindLoaded = true;

          try {
            pagefind = await import("/pagefind/pagefind.js");
            await pagefind.options({
              baseUrl: "/",
              bundlePath: "/pagefind/",
              excerptLength: 25,
              highlightParam: "highlight",
            });
            pagefind.init();
            log("Pagefind loaded");
          } catch (e) {
            error("Pagefind init failed:", e);
          }
        };

        input.addEventListener("focus", initPagefind, {
          once: true,
          passive: true,
        });

        input.addEventListener("input", (e) => {
          clearTimeout(timer);
          const term = e.target.value.trim();

          if (!term) {
            hideResults();
            return;
          }

          setState("loading");

          timer = setTimeout(async () => {
            if (!pagefind) {
              await initPagefind();
              if (!pagefind) {
                setState("error");
                return;
              }
            }

            try {
              const res = await pagefind.search(term);

              if (!res.results.length) {
                setState("empty");
                return;
              }

              suggList.innerHTML = "";
              showResults();

              const fragment = document.createDocumentFragment();
              const results = res.results.slice(0, 8);

              for (const hit of results) {
                try {
                  const data = await hit.data();
                  const li = document.createElement("li");
                  li.innerHTML = `
                <a href="${data.url}">
                  <strong>${data.meta?.title || data.url}</strong>
                  <p>${data.excerpt || ""}</p>
                </a>
              `;
                  fragment.appendChild(li);
                } catch (e) {
                  warn("Result render failed:", e);
                }
              }

              suggList.appendChild(fragment);
            } catch (e) {
              error("Search failed:", e);
              setState("error");
            }
          }, 200);
        });

        suggList.addEventListener(
          "mouseover",
          (e) => {
            const item = e.target.closest("li");
            if (!item || item.classList.contains("search-state")) return;

            const a = item.querySelector("a");
            if (!a) return;

            const title = a.querySelector("strong")?.textContent || "";
            const desc = a.querySelector("p")?.textContent || "";

            preview.innerHTML = `<h4>${title}</h4><p>${desc}</p><small>${a.href}</small>`;
            preview.style.display = "block";
            preview.style.left = `${e.pageX + 12}px`;
            preview.style.top = `${e.pageY + 6}px`;
          },
          { passive: true },
        );

        suggList.addEventListener(
          "mouseleave",
          () => (preview.style.display = "none"),
          { passive: true },
        );
        log("Search initialized");
      }, "Search"),
    900,
  );

  // FILTERS
  defer(
    () =>
      safe(() => {
        if (!FEATURES.filters) return;

        const catSelect = $("#filter-category");
        const subSelect = $("#filter-subcategory");
        const clearButtons = $$(".clear-filters");
        const posts = [...$$(".post-item")];
        const mapEl = $("#categorySubcategoryMap");
        const noRes = $("#noResults");
        const groups = $$(".category-group");

        if (!catSelect || !subSelect || !mapEl || !posts.length) return;

        let map = {};
        try {
          map = JSON.parse(mapEl.textContent);
        } catch (e) {
          return error("Invalid map JSON", e);
        }

        // Detect if we're on a category page by checking the URL path
        const currentPath = window.location.pathname;
        const categoryPageMatch = currentPath.match(
          /^\/categories\/([^\/]+)\/?$/,
        );
        const isCategoryPage = !!categoryPageMatch;
        const currentCategory = categoryPageMatch
          ? categoryPageMatch[1].toLowerCase()
          : null;

        const normalize = (raw = "") =>
          raw
            .split(",")
            .map((v) => v.trim().toLowerCase())
            .filter(Boolean);

        const applyFilters = () => {
          const selectedCat = catSelect.value.toLowerCase();
          const selectedSub = subSelect.value.toLowerCase();
          let visibleCount = 0;

          posts.forEach((post) => {
            const cats = normalize(post.dataset.categories);
            const subs = normalize(post.dataset.tags);
            let show = true;

            if (selectedCat !== "all" && !cats.includes(selectedCat))
              show = false;
            if (
              !subSelect.disabled &&
              selectedSub !== "all" &&
              !subs.includes(selectedSub)
            )
              show = false;

            post.style.display = show ? "" : "none";
            if (show) visibleCount++;
          });

          if (groups.length) {
            groups.forEach((group) => {
              const hasVisible = group.querySelector(
                ".post-item:not([style*='display: none'])",
              );
              group.style.display = hasVisible ? "" : "none";
            });
          }

          noRes?.classList.toggle("hidden", visibleCount > 0);
        };

        const populateSubcategories = (category) => {
          subSelect.innerHTML = `<option value="all">TUTTE</option>`;
          (map[category] || []).forEach((sc) => {
            const opt = document.createElement("option");
            opt.value = sc.value.toLowerCase();
            opt.textContent = sc.label;
            subSelect.appendChild(opt);
          });
          subSelect.disabled = false;
          subSelect.classList.remove("opacity-60", "cursor-not-allowed");
        };

        // Initialize category select based on URL
        const initializeCategorySelect = () => {
          if (isCategoryPage && currentCategory) {
            // Find the matching option
            const currentOption = Array.from(catSelect.options).find(
              (opt) => opt.value.toLowerCase() === currentCategory,
            );

            if (currentOption) {
              catSelect.innerHTML = "";

              // Add "all" option first
              const allOption = document.createElement("option");
              allOption.value = "all";
              allOption.textContent = "TUTTE";
              catSelect.appendChild(allOption);

              // Add current category option
              catSelect.appendChild(currentOption);

              // Set current category as selected
              catSelect.value = currentCategory;

              // Populate subcategories immediately
              populateSubcategories(currentCategory);
            }
          }
        };

        catSelect.addEventListener("change", () => {
          const value = catSelect.value.toLowerCase();
          if (value === "all") {
            subSelect.disabled = true;
            subSelect.innerHTML = `<option>SELEZIONA CATEGORIA</option>`;
            subSelect.classList.add("opacity-60", "cursor-not-allowed");
          } else {
            populateSubcategories(value);
          }
          applyFilters();
        });

        subSelect.addEventListener("change", applyFilters);

        clearButtons.forEach((btn) =>
          btn.addEventListener("click", () => {
            if (isCategoryPage && currentCategory) {
              // On category page: reset to current category
              catSelect.value = currentCategory;
              populateSubcategories(currentCategory);
              subSelect.value = "all";
            } else {
              // On other pages: reset to "all"
              catSelect.value = "all";
              subSelect.disabled = true;
              subSelect.innerHTML = `<option>SELEZIONA CATEGORIA</option>`;
              subSelect.classList.add("opacity-60", "cursor-not-allowed");
            }
            applyFilters();
          }),
        );

        // Initialize and apply filters
        initializeCategorySelect();
        applyFilters();
        log("Filters initialized");
      }, "Filters"),
    1000,
  );

  // SWIPER (only if library loaded)
  defer(
    () =>
      safe(() => {
        if (!FEATURES.swiper || typeof Swiper === "undefined") return;

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
          const slides = $$(".heroTextSwiper .swiper-slide");
          if (!slides.length) return;
          setActiveSlide(slides, 0);
          slides.forEach((slide, i) =>
            slide.addEventListener(
              "mouseenter",
              () => setActiveSlide(slides, i),
              { passive: true },
            ),
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
          window.innerWidth >= 1024
            ? setupDesktopHoverSync()
            : setupMobileSync();
        };

        window.addEventListener("resize", setupHoverSync, { passive: true });
        setupHoverSync();

        new Swiper(".articleSwiper", {
          loop: true,
          slidesPerView: 2,
          spaceBetween: 20,
          autoplay: true,
          navigation: { prevEl: ".prev-article", nextEl: ".next-article" },
          breakpoints: { 1024: { slidesPerView: 4, autoplay: false } },
        });

        log("Swiper initialized");
      }, "Swiper"),
    1100,
  );

  // GLIGHTBOX (only if library loaded)
  defer(
    () =>
      safe(() => {
        if (!FEATURES.glightbox || typeof GLightbox === "undefined") return;

        const items = $$(".glightbox");
        if (!items.length) return;

        GLightbox({
          selector: ".glightbox",
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
        log("Lightbox initialized");
      }, "Lightbox"),
    1200,
  );

  // NEWSLETTER
  defer(
    () =>
      safe(() => {
        if (!FEATURES.newsletter) return;

        const form = $(".hn-form");
        if (!form) return;

        const emailInput = $("#newsletter-email");
        const button = form.querySelector("button");
        if (!emailInput || !button) return;

        form.addEventListener("submit", async (e) => {
          e.preventDefault();
          const email = emailInput.value.trim();
          if (!email) return;

          button.disabled = true;

          try {
            const res = await fetch("/.netlify/functions/subscribe", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ email }),
            });

            if (res.ok) {
              form.reset();
              alert("🎉 Sei iscritto alla newsletter!");
            } else {
              alert("❌ Errore durante l'iscrizione.");
            }
          } catch (e) {
            error("Newsletter failed:", e);
            alert("❌ Connessione fallita.");
          } finally {
            button.disabled = false;
          }
        });
        log("Newsletter initialized");
      }, "Newsletter"),
    1300,
  );

  // FAQ ACCORDION
  defer(
    () =>
      safe(() => {
        if (!FEATURES.faq) return;

        const toggles = $$("[id^='faq-toggle-']");
        if (!toggles.length) return;

        // Store FAQ state for efficient toggling
        const faqItems = Array.from(toggles)
          .map((toggle) => {
            const contentId = toggle.getAttribute("aria-controls");
            const content = contentId
              ? document.getElementById(contentId)
              : null;
            // Get the icon span: button > span (wrapper) > span (icon)
            const iconWrapper = toggle.querySelector("span");
            const icon = iconWrapper ? iconWrapper.querySelector("span") : null;

            return { toggle, content, icon };
          })
          .filter((item) => item.content && item.icon);

        if (!faqItems.length) {
          warn("FAQ items not found or missing elements");
          return;
        }

        const closeFAQ = (item) => {
          item.toggle.setAttribute("aria-expanded", "false");
          item.content.classList.add(
            "max-h-0",
            "opacity-0",
            "pointer-events-none",
          );
          item.content.classList.remove("max-h-50", "opacity-100");
          item.icon.textContent = "+";
        };

        const openFAQ = (item) => {
          item.toggle.setAttribute("aria-expanded", "true");
          item.content.classList.remove(
            "max-h-0",
            "opacity-0",
            "pointer-events-none",
          );
          item.content.classList.add("max-h-50", "opacity-100");
          item.icon.textContent = "-";
        };

        faqItems.forEach((item, index) => {
          item.toggle.addEventListener("click", () => {
            const isExpanded =
              item.toggle.getAttribute("aria-expanded") === "true";
            // Close all other FAQs (accordion behavior)
            faqItems.forEach((otherItem, otherIndex) => {
              if (
                otherIndex !== index &&
                otherItem.toggle.getAttribute("aria-expanded") === "true"
              ) {
                closeFAQ(otherItem);
              }
            });
            // Toggle current FAQ
            if (isExpanded) {
              closeFAQ(item);
            } else {
              openFAQ(item);
            }
          });
        });
        log(`FAQ accordion initialized (${faqItems.length} items)`);
      }, "FAQ"),
    1400,
  );
};

/* ===========================
INITIALIZATION SEQUENCE
=========================== */
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    initCritical();
    // Defer non-critical features until after first paint
    if (document.readyState === "complete") {
      initDeferred();
    } else {
      window.addEventListener("load", initDeferred, {
        once: true,
        passive: true,
      });
    }
  });
} else {
  // DOM already loaded
  initCritical();
  if (document.readyState === "complete") {
    initDeferred();
  } else {
    window.addEventListener("load", initDeferred, {
      once: true,
      passive: true,
    });
  }
}