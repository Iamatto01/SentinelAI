import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

export default function Tooltip({ children, content, shortcut, position = 'top', className = '' }) {
  const [isVisible, setIsVisible] = useState(false);

  // Position styles based on the 'position' prop
  const getPositionStyles = () => {
    switch (position) {
      case 'bottom':
        return { top: '100%', left: '50%', transform: 'translateX(-50%)', marginTop: '8px' };
      case 'left':
        return { right: '100%', top: '50%', transform: 'translateY(-50%)', marginRight: '8px' };
      case 'right':
        return { left: '100%', top: '50%', transform: 'translateY(-50%)', marginLeft: '8px' };
      case 'top':
      default:
        return { bottom: '100%', left: '50%', transform: 'translateX(-50%)', marginBottom: '8px' };
    }
  };

  return (
    <div 
      className={`relative flex items-center justify-center ${className}`}
      onMouseEnter={() => setIsVisible(true)}
      onMouseLeave={() => setIsVisible(false)}
    >
      {children}
      
      <AnimatePresence>
        {isVisible && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            style={{ ...getPositionStyles(), position: 'absolute' }}
            className="z-50 px-3 py-2 text-sm text-white bg-black/90 border border-white/10 rounded-xl shadow-xl backdrop-blur-md whitespace-nowrap pointer-events-none flex items-center gap-2"
          >
            <span className="font-medium">{content}</span>
            {shortcut && (
              <span className="px-1.5 py-0.5 text-[10px] uppercase font-bold tracking-wider bg-white/20 rounded text-white/80">
                {shortcut}
              </span>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
