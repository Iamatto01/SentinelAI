/**
 * Framer Motion animation variants for SentinelAI
 * iOS-style fluid animations with physics-based motion
 */

// Staggered container for children animations
export const staggerContainer = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.1,
    },
  },
};

// Fade in from different directions
export const fadeInLeft = {
  hidden: { opacity: 0, x: -60 },
  show: {
    opacity: 1,
    x: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 200,
    },
  },
};

export const fadeInRight = {
  hidden: { opacity: 0, x: 60 },
  show: {
    opacity: 1,
    x: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 200,
    },
  },
};

export const fadeInUp = {
  hidden: { opacity: 0, y: 40 },
  show: {
    opacity: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 200,
    },
  },
};

export const fadeInDown = {
  hidden: { opacity: 0, y: -40 },
  show: {
    opacity: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 200,
    },
  },
};

// Scale with bounce effect (iOS-style)
export const scaleIn = {
  hidden: { opacity: 0, scale: 0.8 },
  show: {
    opacity: 1,
    scale: 1,
    transition: {
      type: 'spring',
      damping: 20,
      stiffness: 300,
    },
  },
};

// Floating animation for decorative elements
export const float = {
  animate: {
    y: [0, -10, 0],
    transition: {
      duration: 3,
      repeat: Infinity,
      ease: 'easeInOut',
    },
  },
};

// Subtle rotate animation
export const rotate = {
  animate: {
    rotate: [0, 5, -5, 0],
    transition: {
      duration: 6,
      repeat: Infinity,
      ease: 'easeInOut',
    },
  },
};

// Glass card hover effect
export const glassCardHover = {
  rest: {
    scale: 1,
    y: 0,
    boxShadow: '0 4px 30px rgba(255, 255, 255, 0.05)',
  },
  hover: {
    scale: 1.02,
    y: -4,
    boxShadow: '0 20px 40px rgba(255, 255, 255, 0.1)',
    transition: {
      type: 'spring',
      damping: 20,
      stiffness: 300,
    },
  },
  tap: {
    scale: 0.98,
  },
};

// Button press effect (iOS haptic-like)
export const buttonTap = {
  rest: { scale: 1 },
  hover: { scale: 1.02 },
  tap: { scale: 0.95 },
};

// Page transition
export const pageTransition = {
  initial: { opacity: 0, y: 20 },
  animate: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.4,
      ease: [0.25, 0.46, 0.45, 0.94],
    },
  },
  exit: {
    opacity: 0,
    y: -20,
    transition: {
      duration: 0.3,
    },
  },
};

// Sidebar slide
export const sidebarSlide = {
  hidden: { x: -100, opacity: 0 },
  show: {
    x: 0,
    opacity: 1,
    transition: {
      type: 'spring',
      damping: 30,
      stiffness: 200,
    },
  },
};

// Notification pop
export const notificationPop = {
  hidden: { opacity: 0, scale: 0.5, y: -20 },
  show: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 15,
      stiffness: 400,
    },
  },
  exit: {
    opacity: 0,
    scale: 0.5,
    y: -20,
    transition: {
      duration: 0.2,
    },
  },
};

// Physics-based draggable orb
export const floatingOrb = (delay = 0) => ({
  animate: {
    x: [0, 30, -20, 10, 0],
    y: [0, -20, 15, -10, 0],
    scale: [1, 1.1, 0.95, 1.05, 1],
    transition: {
      duration: 8,
      delay,
      repeat: Infinity,
      ease: 'easeInOut',
    },
  },
});

// Modal animation
export const modalBackdrop = {
  hidden: { opacity: 0 },
  show: { opacity: 1 },
  exit: { opacity: 0 },
};

export const modalContent = {
  hidden: { opacity: 0, scale: 0.9, y: 20 },
  show: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 300,
    },
  },
  exit: {
    opacity: 0,
    scale: 0.9,
    y: 20,
    transition: {
      duration: 0.2,
    },
  },
};

// List item stagger (for tables/lists)
export const listItem = {
  hidden: { opacity: 0, x: -20 },
  show: {
    opacity: 1,
    x: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 200,
    },
  },
};

// Metric card entrance (different direction per index)
export const metricCardVariant = (index) => {
  const directions = [
    { x: -60, y: -30 }, // top-left
    { x: 60, y: -30 },  // top-right
    { x: -60, y: 30 },  // bottom-left
    { x: 60, y: 30 },   // bottom-right
  ];
  const dir = directions[index % 4];
  return {
    hidden: { opacity: 0, x: dir.x, y: dir.y },
    show: {
      opacity: 1,
      x: 0,
      y: 0,
      transition: {
        type: 'spring',
        damping: 20,
        stiffness: 150,
        delay: index * 0.1,
      },
    },
  };
};
