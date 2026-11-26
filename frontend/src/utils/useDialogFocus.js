import { useEffect } from "react";

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'summary',
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

/**
 * Accessible keyboard focus management for custom modal dialogs and drawers:
 * - Saves the element that had focus before opening
 * - Moves initial focus into the dialog
 * - Traps Tab / Shift+Tab within the dialog while open
 * - Closes on Escape and restores focus to the invoker
 */
export function useDialogFocus(isOpen, onClose, containerRef) {
  useEffect(() => {
    if (!isOpen) return;
    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const container = containerRef.current;
    if (container) {
      const focusables = container.querySelectorAll(FOCUSABLE_SELECTOR);
      const target = focusables[0] instanceof HTMLElement ? focusables[0] : container;
      if (typeof target.focus === "function") {
        target.focus();
      }
    }

    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !containerRef.current) return;

      const focusables = Array.from(
        containerRef.current.querySelectorAll(FOCUSABLE_SELECTOR)
      ).filter((el) => el instanceof HTMLElement && el.offsetParent !== null);

      if (focusables.length === 0) {
        e.preventDefault();
        containerRef.current.focus();
        return;
      }

      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (previouslyFocused && document.contains(previouslyFocused)) {
        previouslyFocused.focus();
      }
    };
  }, [isOpen, onClose, containerRef]);
}
