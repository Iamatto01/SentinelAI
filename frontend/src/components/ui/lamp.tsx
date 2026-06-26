"use client";
import React from "react";
import { motion } from "motion/react";
import { cn } from "@/lib/utils";

export default function LampDemo() {
  return (
    <LampContainer>
      <motion.h1
        initial={{ opacity: 0.5, y: 100 }}
        whileInView={{ opacity: 1, y: 0 }}
        transition={{
          delay: 0.3,
          duration: 0.8,
          ease: "easeInOut",
        }}
        className="mt-8 bg-gradient-to-br from-slate-300 to-slate-500 py-4 bg-clip-text text-center text-4xl font-medium tracking-tight text-transparent md:text-7xl"
      >
        Build lamps <br /> the right way
      </motion.h1>
    </LampContainer>
  );
}

export const LampContainer = ({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) => {
  const [isSmallScreen, setIsSmallScreen] = React.useState(() =>
    typeof window === "undefined" ? false : window.innerWidth < 640
  );

  React.useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const onResize = () => setIsSmallScreen(window.innerWidth < 640);
    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const lampTurnOnTransition = {
    delay: 0.2,
    duration: 1.2,
    ease: "circOut",
  } as const;

  const lampPulseTransition = {
    duration: 4.4,
    times: [0, 0.35, 0.5, 1],
    ease: "easeInOut",
    repeat: Infinity,
    repeatDelay: 1.2,
  } as const;

  return (
    <div
      className={cn(
        "relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-transparent w-full rounded-md z-0",
        className
      )}
    >
      <div className="relative flex w-full flex-1 scale-125 md:scale-[1.3] scale-y-[1.4] items-center justify-center isolate z-0 pt-4">
        <motion.div
          initial={{ opacity: 1, width: "30rem" }}
          animate={{ opacity: [1, 1, 0.18, 1], width: ["30rem", "30rem", "8rem", "30rem"] }}
          transition={lampPulseTransition}
          style={{
            backgroundImage: `conic-gradient(var(--conic-position), var(--tw-gradient-stops))`,
          }}
          className="absolute inset-auto right-1/2 h-56 overflow-visible w-[30rem] bg-gradient-conic from-cyan-500 via-transparent to-transparent text-white [--conic-position:from_70deg_at_center_top]"
        >
          <div className="absolute  w-[100%] left-0 bg-slate-950 h-40 bottom-0 z-20 [mask-image:linear-gradient(to_top,white,transparent)]" />
          <div className="absolute  w-40 h-[100%] left-0 bg-slate-950  bottom-0 z-20 [mask-image:linear-gradient(to_right,white,transparent)]" />
        </motion.div>
        <motion.div
          initial={{ opacity: 1, width: "30rem" }}
          animate={{ opacity: [1, 1, 0.18, 1], width: ["30rem", "30rem", "8rem", "30rem"] }}
          transition={lampPulseTransition}
          style={{
            backgroundImage: `conic-gradient(var(--conic-position), var(--tw-gradient-stops))`,
          }}
          className="absolute inset-auto left-1/2 h-56 w-[30rem] bg-gradient-conic from-transparent via-transparent to-cyan-500 text-white [--conic-position:from_290deg_at_center_top]"
        >
          <div className="absolute  w-40 h-[100%] right-0 bg-slate-950  bottom-0 z-20 [mask-image:linear-gradient(to_left,white,transparent)]" />
          <div className="absolute  w-[100%] right-0 bg-slate-950 h-40 bottom-0 z-20 [mask-image:linear-gradient(to_top,white,transparent)]" />
        </motion.div>
        <div className="absolute top-1/2 h-48 w-full translate-y-12 scale-x-150 bg-slate-950 blur-2xl"></div>
        <div className="absolute top-1/2 z-50 h-48 w-full bg-transparent opacity-10 backdrop-blur-md"></div>
        <motion.div
          className="absolute inset-auto z-50 h-36 w-[28rem] -translate-y-1/2 rounded-full bg-cyan-500 opacity-50 blur-3xl"
          initial={{ opacity: 0.5 }}
          animate={{ opacity: [0.5, 0.5, 0.08, 0.5], scaleX: [1, 1, 0.45, 1] }}
          transition={lampPulseTransition}
        ></motion.div>
        <motion.div
          initial={{ width: "16rem" }}
          animate={{ width: ["16rem", "16rem", "4rem", "16rem"], opacity: [1, 1, 0.18, 1] }}
          transition={lampPulseTransition}
          className="absolute inset-auto z-30 h-36 w-64 -translate-y-[6rem] rounded-full bg-cyan-400 blur-2xl"
        ></motion.div>
        <motion.div
          initial={{ width: "30rem" }}
          animate={{ width: ["30rem", "30rem", "6rem", "30rem"], opacity: [1, 1, 0.2, 1] }}
          transition={lampPulseTransition}
          className="absolute inset-auto z-50 h-0.5 w-[30rem] -translate-y-[7rem] bg-cyan-400 "
        ></motion.div>

        <motion.div
          className="absolute inset-auto z-40 h-44 w-full -translate-y-[12.5rem] bg-slate-950 "
          initial={{ opacity: 1 }}
          animate={{ opacity: [1, 1, 0.72, 1], translateY: ["-12.5rem", "-12.5rem", "-10rem", "-12.5rem"] }}
          transition={lampPulseTransition}
        ></motion.div>
      </div>

      <div className="relative z-50 flex -translate-y-2 md:-translate-y-4 flex-col items-center px-5">
        {children}
      </div>
    </div>
  );
};