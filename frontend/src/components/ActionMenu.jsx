import { useState, useEffect, useRef } from 'react';

export default function ActionMenu({ items, triggerLabel }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      <button
        className="text-gray-400 hover:text-white p-1 rounded hover:bg-white/10 transition-all"
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
      >
        {triggerLabel || '\u22EF'}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 w-48 glassmorphism rounded-lg border border-white/20 shadow-xl z-50 py-1">
          {items.map((item, i) => {
            if (item.divider) {
              return <div key={`div-${i}`} className="border-t border-white/10 my-1" />;
            }
            return (
              <button
                key={item.label}
                className={`w-full text-left px-4 py-2 text-sm hover:bg-white/10 transition-all ${item.danger ? 'text-red-400' : 'text-gray-200'}`}
                onClick={(e) => {
                  e.stopPropagation();
                  setOpen(false);
                  item.onClick?.();
                }}
              >
                {item.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
