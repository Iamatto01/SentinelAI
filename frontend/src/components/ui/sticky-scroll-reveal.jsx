import React, { useRef } from 'react';
import { useScroll, motion, useMotionValueEvent } from 'framer-motion';

export const StickyScroll = ({ content }) => {
  const [activeCard, setActiveCard] = React.useState(0);
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start start', 'end start'],
  });
  const cardLength = content.length;

  useMotionValueEvent(scrollYProgress, 'change', (latest) => {
    const cardsBreakpoints = content.map((_, index) => index / cardLength);
    const closestBreakpointIndex = cardsBreakpoints.reduce(
      (acc, breakpoint, index) => {
        const distance = Math.abs(latest - breakpoint);
        if (distance < Math.abs(latest - cardsBreakpoints[acc])) {
          return index;
        }
        return acc;
      },
      0
    );
    setActiveCard(closestBreakpointIndex);
  });

  return (
    <motion.div
      className="flex justify-center relative space-x-10 rounded-2xl p-6 md:p-10"
      ref={ref}
    >
      <div className="relative flex items-start max-w-5xl mx-auto w-full">
        {/* Text Section */}
        <div className="w-full md:w-1/2 pr-8 pb-32">
          {content.map((item, index) => (
            <div key={item.title + index} className="mt-20 mb-32 first:mt-0">
              <motion.div
                initial={{ opacity: 0 }}
                animate={{
                  opacity: activeCard === index ? 1 : 0.3,
                }}
                className="flex items-center gap-4 mb-4"
              >
                {item.icon && (
                  <div
                    className={`p-3 rounded-lg flex items-center justify-center transition-colors ${
                      activeCard === index
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'bg-white/5 text-gray-500 border border-white/5'
                    }`}
                  >
                    <item.icon size={24} />
                  </div>
                )}
                <h3
                  className={`text-2xl md:text-3xl font-bold transition-colors ${
                    activeCard === index ? 'text-white' : 'text-gray-500'
                  }`}
                >
                  {item.title}
                </h3>
              </motion.div>
              <motion.p
                initial={{ opacity: 0 }}
                animate={{
                  opacity: activeCard === index ? 1 : 0.3,
                }}
                className="text-lg text-gray-300 max-w-sm ml-[60px]"
              >
                {item.description}
              </motion.p>
            </div>
          ))}
          <div className="h-40" />
        </div>

        {/* Sticky Visual Section */}
        <div
          className="hidden md:flex w-1/2 h-[400px] sticky top-32 rounded-xl bg-white/[0.03] border border-white/10 backdrop-blur-xl overflow-hidden"
        >
          {content.map((item, index) => (
            <motion.div
              key={item.title + index}
              initial={{ opacity: 0, y: 20 }}
              animate={{
                opacity: activeCard === index ? 1 : 0,
                y: activeCard === index ? 0 : 20,
              }}
              transition={{ duration: 0.5 }}
              className="absolute inset-0 flex items-center justify-center p-8"
              style={{ display: activeCard === index ? 'flex' : 'none' }}
            >
              <div className="text-center">
                {item.icon && (
                  <div className="mx-auto w-24 h-24 mb-6 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center border border-cyan-500/30">
                    <item.icon size={48} className="text-cyan-400" />
                  </div>
                )}
                <h4 className="text-xl font-semibold text-white mb-3">{item.title}</h4>
                <p className="text-gray-400 text-sm leading-relaxed">{item.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  );
};
