import { useEffect } from 'react';

/**
 * useShortcut - A hook to bind keyboard shortcuts to callbacks
 * @param {string} key - The main key (e.g., 'n', 's', 'c', '1'). Case-insensitive.
 * @param {Function} callback - The function to call when shortcut is triggered
 * @param {Object} options - Modifier keys (alt, ctrl, shift)
 */
export default function useShortcut(key, callback, options = { alt: true }) {
  useEffect(() => {
    function handleKeyDown(e) {
      // Check if user is typing in an input or textarea
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
        return;
      }

      // Check modifier keys
      const altMatch = options.alt ? e.altKey : !e.altKey;
      const ctrlMatch = options.ctrl ? (e.ctrlKey || e.metaKey) : (!e.ctrlKey && !e.metaKey);
      const shiftMatch = options.shift ? e.shiftKey : !e.shiftKey;

      if (altMatch && ctrlMatch && shiftMatch && e.key.toLowerCase() === key.toLowerCase()) {
        e.preventDefault();
        callback(e);
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [key, callback, options]);
}
