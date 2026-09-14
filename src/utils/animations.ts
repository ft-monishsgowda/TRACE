import { animate, stagger } from 'animejs';

/**
 * Utility functions powered by Anime.js for smooth, human-perceptible UI transitions.
 * Paced intentionally with deliberate eases so the motion is felt clearly.
 */

export const animateViewTransition = (target: HTMLElement | null | string) => {
  if (!target) return;
  try {
    animate(target, {
      opacity: [0, 1],
      translateY: [16, 0],
      duration: 650,
      ease: 'outCubic',
    });
  } catch (e) {
    console.debug('Animation note:', e);
  }
};

export const animateStaggerItems = (selectorOrElements: HTMLElement[] | string, delay = 80) => {
  if (!selectorOrElements) return;
  try {
    animate(selectorOrElements, {
      opacity: [0, 1],
      translateY: [16, 0],
      delay: stagger(delay, { start: 100 }),
      duration: 650,
      ease: 'outCubic',
    });
  } catch (e) {
    console.debug('Animation note:', e);
  }
};

export const animateNumber = (
  targetElem: HTMLElement | null,
  startValue: number,
  endValue: number,
  duration = 1400,
  prefix = '',
  suffix = ''
) => {
  if (!targetElem) return;
  const obj = { val: startValue };
  try {
    animate(obj, {
      val: endValue,
      duration,
      ease: 'outCubic',
      onUpdate: () => {
        if (targetElem) {
          targetElem.textContent = `${prefix}${Math.round(obj.val)}${suffix}`;
        }
      },
    });
  } catch (e) {
    if (targetElem) targetElem.textContent = `${prefix}${endValue}${suffix}`;
  }
};

export const animateGaugeCircle = (
  circleElem: SVGCircleElement | null,
  targetOffset: number,
  circumference: number,
  duration = 1500
) => {
  if (!circleElem) return;
  try {
    animate(circleElem, {
      strokeDashoffset: [circumference, targetOffset],
      duration,
      ease: 'outCubic',
    });
  } catch (e) {
    if (circleElem) circleElem.style.strokeDashoffset = `${targetOffset}`;
  }
};

export const animateBarWidth = (
  barElem: HTMLElement | null,
  targetPercent: number,
  duration = 1100
) => {
  if (!barElem) return;
  try {
    animate(barElem, {
      width: ['0%', `${targetPercent}%`],
      duration,
      ease: 'outCubic',
    });
  } catch (e) {
    if (barElem) barElem.style.width = `${targetPercent}%`;
  }
};

/**
 * Tiny minimal scroll reveal observer powered by Anime.js.
 * Gently fades in and lifts elements with human-perceptible pacing as they enter viewport.
 */
export const initScrollReveal = (selector = '.scroll-reveal-item') => {
  if (typeof window === 'undefined' || !('IntersectionObserver' in window)) return () => {};

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const el = entry.target as HTMLElement;
          try {
            animate(el, {
              opacity: [0, 1],
              translateY: [20, 0],
              duration: 750,
              ease: 'outCubic',
            });
          } catch {
            el.style.opacity = '1';
            el.style.transform = 'none';
          }
          observer.unobserve(el);
        }
      });
    },
    { threshold: 0.1, rootMargin: '0px 0px -50px 0px' }
  );

  const elements = document.querySelectorAll(selector);
  elements.forEach((el) => {
    (el as HTMLElement).style.opacity = '0';
    observer.observe(el);
  });

  return () => observer.disconnect();
};


