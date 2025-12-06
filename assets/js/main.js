"use strict";

/* ===========================
  GLOBAL DEBUG & LOGGING
=========================== */
const DEBUG = false; // set to FALSE in production

const log = (...args) => DEBUG && console.log("🟢", ...args);
const warn = (...args) => DEBUG && console.warn("🟡", ...args);
const error = (...args) => console.error("🔴", ...args);

/* ===========================
   GLOBAL ERROR CAPTURING
=========================== */
window.addEventListener("error", (e) => {
  error("GLOBAL ERROR:", e.message, e.filename, e.lineno);
});

window.addEventListener("unhandledrejection", (e) => {
  error("PROMISE ERROR:", e.reason);
});

/* ===========================
   FEATURE TOGGLES
=========================== */
const FEATURES = {
  menu: true,
  header: true,
  typewriter: true,
  grid: true,
  counters: true,
  aos: true,
  swiper: true,
};

/* ===========================
   DOM READY
=========================== */
document.addEventListener("DOMContentLoaded", () => {
  log("DOM fully loaded");

  /* ===========================
     SAFE SELECTORS
  ============================ */
  const safeQuery = (selector) => document.querySelector(selector);
  const safeQueryAll = (selector) => document.querySelectorAll(selector);

  const menuToggler = safeQuery(".menuToggler");
  const menu = safeQuery(".menu");
  const header = safeQuery(".header");
  const headerBar = safeQuery(".headerBar");
  const headerLogo = safeQuery(".headerLogo");

  const grid = safeQuery("#stats-grid");
  const cards = safeQueryAll(".card-spotlight");
  const counters = safeQueryAll(".card-spotlight span");

  /* ===========================
     MENU TOGGLE
  ============================ */
  try {
    if (FEATURES.menu && menuToggler && menu) {
      log("Menu system initialized");

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
    } else {
      warn("Menu skipped");
    }
  } catch (e) {
    error("Menu crash:", e);
  }

  /* ===========================
     HEADER SCROLL
  ============================ */
  try {
    if (FEATURES.header && header && headerBar && headerLogo && menu) {
      log("Header scroll effect enabled");

      let isScrolled = false;

      function handleScroll() {
        const shouldBeScrolled = window.scrollY > 0;
        isScrolled = shouldBeScrolled;

        header.classList.toggle("header-glass", shouldBeScrolled);
        headerBar.classList.toggle("py-3", !shouldBeScrolled);
        headerBar.classList.toggle("py-1", shouldBeScrolled);
      }

      handleScroll();
      window.addEventListener("scroll", () => {
        requestAnimationFrame(handleScroll);
      });
    } else {
      warn("Header scroll skipped");
    }
  } catch (e) {
    error("Header crash:", e);
  }

  /* ===========================
     TYPEWRITER
  ============================ */
  try {
    if (FEATURES.typewriter) {
      const dataContainer = safeQuery("#typewriter-data");
      const target = safeQuery("#typewriter");

      if (!dataContainer || !target) {
        warn("Typewriter skipped (missing elements)");
      } else {
        log("Typewriter initialized");

        const words = Array.from(dataContainer.children).map((s) =>
          s.textContent.trim()
        );

        if (words.length) {
          let wordIndex = 0;
          let charIndex = 0;
          let isDeleting = false;
          let pendingPause = false;

          const TYPING_SPEED = 90;
          const DELETING_SPEED = 50;
          const HOLD_AFTER_TYPE = 2200;
          const HOLD_AFTER_DELETE = 400;

          function typeEffect() {
            const currentWord = words[wordIndex];
            let nextDelay = isDeleting ? DELETING_SPEED : TYPING_SPEED;

            if (!isDeleting) {
              if (charIndex < currentWord.length) {
                charIndex++;
                target.textContent = currentWord.substring(0, charIndex);
              } else {
                if (!pendingPause) {
                  pendingPause = true;
                  nextDelay = HOLD_AFTER_TYPE;
                } else {
                  pendingPause = false;
                  isDeleting = true;
                }
              }
            } else {
              if (charIndex > 0) {
                charIndex--;
                target.textContent = currentWord.substring(0, charIndex);
              } else {
                isDeleting = false;
                wordIndex = (wordIndex + 1) % words.length;
                nextDelay = HOLD_AFTER_DELETE;
              }
            }

            setTimeout(typeEffect, nextDelay);
          }

          typeEffect();
        } else {
          warn("Typewriter skipped (no words found)");
        }
      }
    } else {
      warn("Typewriter feature disabled");
    }
  } catch (e) {
    error("Typewriter crash:", e);
  }

  /* ===========================
     GRID HOVER
  ============================ */
  try {
    if (FEATURES.grid && grid && cards.length) {
      log("Grid hover enabled");

      grid.addEventListener("mousemove", (e) => {
        const gx = e.clientX;
        const gy = e.clientY;

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
        cards.forEach((card) => {
          card.style.setProperty("--o", `0`);
        });
      });
    } else {
      warn("Grid hover skipped");
    }
  } catch (e) {
    error("Grid crash:", e);
  }

  /* ===========================
    COUNTERS
  ============================ */
  try {
    if (FEATURES.counters && counters.length) {
      log("Counters initialized");

      counters.forEach((span) => {
        const finalText = span.textContent.trim();
        const isNumber = /^[0-9]+/.test(finalText);
        const duration = 2000;
        const delay = 800;
        let started = false;

        // Reset initial text
        span.textContent = isNumber ? "0" : "";

        const animate = () => {
          if (started) return;
          started = true;

          if (isNumber) {
            const match = finalText.match(/^(\d+)(.*)$/);
            if (!match) return;

            const target = parseInt(match[1], 10);
            const suffix = match[2] || "";
            const startTime = performance.now();

            function update(time) {
              const progress = Math.min((time - startTime) / duration, 1);
              const value = Math.floor(progress * target);
              span.textContent = value + suffix;

              if (progress < 1) {
                requestAnimationFrame(update);
              } else {
                span.textContent = finalText;
              }
            }

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

              if (frame <= finalText.length) {
                setTimeout(scramble, 30);
              } else {
                span.textContent = finalText;
              }
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
    } else {
      warn("Counters skipped");
    }
  } catch (e) {
    error("Counters crash:", e);
  }

  /* ===========================
    PLUGINS
  ============================ */
  try {
    if (FEATURES.aos && typeof AOS !== "undefined") {
      AOS.init({
        offset: 1, // default is 120
        duration: 500,
        easing: "ease-out",
        anchorPlacement: 'top-bottom'
      });
      log("AOS initialized");
    } else {
      warn("AOS skipped");
    }

    if (FEATURES.swiper && typeof Swiper !== "undefined") {
      let heroImgSwiper = new Swiper('.heroImgSwiper', {
        loop: true,
        spaceBetween: 10,
        pagination: {
          el: ".hero-swiper-pagination",
          clickable: true
        },
        breakpoints: {
          1024: {
            allowTouchMove: false,
            noSwiping: true,
            pagination: {
              clickable: false
            }
          }
        }
      });

      let heroTextSwiper = new Swiper('.heroTextSwiper', {
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
          }
        }
      });

      // Small screen (default)
      if (window.innerWidth < 1024) {
        heroImgSwiper.controller.control = heroTextSwiper;
      }

      /* -------------------------------------------
        LARGE SCREEN BEHAVIOR (hover sync)
      -------------------------------------------- */
      let desktopAutoPlayInterval = null;
      const AUTOPLAY_DELAY = 5000;

      function clearDesktopAutoplay() {
        if (desktopAutoPlayInterval) {
          clearInterval(desktopAutoPlayInterval);
          desktopAutoPlayInterval = null;
        }
      }

      function setActiveSlide(slides, index) {
        slides.forEach(s => s.classList.remove('swiper-slide-active'));
        slides[index].classList.add('swiper-slide-active');

        heroImgSwiper.slideToLoop(index);
      }

      function setupDesktopHoverSync() {
        heroTextSwiper.destroy();
        clearDesktopAutoplay();

        const slides = safeQueryAll('.heroTextSwiper .swiper-slide');
        if (slides.length === 0) return;

        setActiveSlide(slides, 0);

        slides.forEach((slide, index) => {
          slide.addEventListener('mouseenter', () => {
            setActiveSlide(slides, index);
          });
        });

        let currentIndex = 0;
        desktopAutoPlayInterval = setInterval(() => {
          currentIndex = (currentIndex + 1) % slides.length;
          setActiveSlide(slides, currentIndex);
        }, AUTOPLAY_DELAY);
      }

      function setupMobileSync() {
        clearDesktopAutoplay();
        heroImgSwiper.controller.control = heroTextSwiper;
      }

      function setupHoverSync() {
        if (window.innerWidth >= 1024) {
          setupDesktopHoverSync();
        } else {
          setupMobileSync();
        }
      }

      window.addEventListener('resize', setupHoverSync);
      setupHoverSync();

      setupHoverSync();
      window.addEventListener('resize', setupHoverSync);

      let articleSwiper = new Swiper('.articleSwiper', {
        loop: true,
        slidesPerView: 2,
        spaceBetween: 20,
        autoplay: true,
        navigation: {
          prevEl: ".prev-article",
          nextEl: ".next-article"
        },
        breakpoints: {
          1024: {
            slidesPerView: 4,
            autoplay: false
          }
        }
      });
      log("Swiper initialized");
    } else {
      warn("Swiper skipped");
    }
  } catch (e) {
    error("Plugin crash:", e);
  }
});