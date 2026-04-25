"use client";
import React from "react";
import {
  motion,
  useScroll,
  useTransform,
  useSpring,
  MotionValue,
} from "motion/react";



export const HeroParallax = ({
  products,
  children,
}: {
  products: {
    title: string;
    link: string;
    thumbnail: string;
  }[];
  children?: React.ReactNode;
}) => {
  const ref = React.useRef(null);
  const [viewportWidth, setViewportWidth] = React.useState(() =>
    typeof window === "undefined" ? 1440 : window.innerWidth
  );

  React.useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    const onResize = () => setViewportWidth(window.innerWidth);
    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const isMobile = viewportWidth < 768;
  const isTablet = viewportWidth < 1024;

  const firstCount = isMobile ? 3 : isTablet ? 4 : 5;
  const secondCount = isMobile ? 3 : isTablet ? 4 : 5;
  const thirdCount = isMobile ? 0 : isTablet ? 4 : 5;

  const firstRow = products.slice(0, firstCount);
  const secondRow = products.slice(firstCount, firstCount + secondCount);
  const thirdRow = thirdCount
    ? products.slice(
        firstCount + secondCount,
        firstCount + secondCount + thirdCount
      )
    : [];

  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start start", "end start"],
  });

  const springConfig = { stiffness: 300, damping: 30, bounce: 100 };
  const travelX = isMobile ? 220 : isTablet ? 520 : 1000;
  const rotateXStart = isMobile ? 8 : isTablet ? 11 : 15;
  const rotateZStart = isMobile ? 10 : isTablet ? 14 : 20;
  const translateYFrom = isMobile ? -180 : isTablet ? -380 : -700;
  const translateYTo = isMobile ? 140 : isTablet ? 300 : 500;

  const translateX = useSpring(
    useTransform(scrollYProgress, [0, 1], [0, travelX]),
    springConfig
  );
  const translateXReverse = useSpring(
    useTransform(scrollYProgress, [0, 1], [0, -travelX]),
    springConfig
  );
  const rotateX = useSpring(
    useTransform(scrollYProgress, [0, 0.2], [rotateXStart, 0]),
    springConfig
  );
  const opacity = useSpring(
    useTransform(scrollYProgress, [0, 0.2], [0.2, 1]),
    springConfig
  );
  const rotateZ = useSpring(
    useTransform(scrollYProgress, [0, 0.2], [rotateZStart, 0]),
    springConfig
  );
  const translateY = useSpring(
    useTransform(scrollYProgress, [0, 0.2], [translateYFrom, translateYTo]),
    springConfig
  );

  const shellClassName =
    "overflow-hidden antialiased relative flex flex-col self-auto [perspective:1000px] [transform-style:preserve-3d]";

  const shellHeightClass = isMobile
    ? "h-[165vh] py-14"
    : isTablet
      ? "h-[220vh] py-24"
      : "h-[300vh] py-40";

  const rowSpacingClass = isMobile
    ? "mb-8 gap-4 px-4"
    : isTablet
      ? "mb-12 gap-8 px-4"
      : "mb-20 gap-20";

  return (
    <div
      ref={ref}
      className={`${shellClassName} ${shellHeightClass}`}
    >
      {children ? children : <Header />}
      <motion.div
        style={{
          rotateX,
          rotateZ,
          translateY,
          opacity,
        }}
        className=""
      >
        <motion.div className={`flex flex-row-reverse ${rowSpacingClass}`}>
          {firstRow.map((product) => (
            <ProductCard
              product={product}
              translate={translateX}
              key={product.title}
            />
          ))}
        </motion.div>
        <motion.div className={`flex flex-row ${rowSpacingClass}`}>
          {secondRow.map((product) => (
            <ProductCard
              product={product}
              translate={translateXReverse}
              key={product.title}
            />
          ))}
        </motion.div>
        {thirdRow.length > 0 && (
          <motion.div className={`flex flex-row-reverse ${rowSpacingClass}`}>
            {thirdRow.map((product) => (
              <ProductCard
                product={product}
                translate={translateX}
                key={product.title}
              />
            ))}
          </motion.div>
        )}
      </motion.div>
    </div>
  );
};

export const Header = () => {
  return (
    <div className="max-w-7xl relative mx-auto py-20 md:py-40 px-4 w-full  left-0 top-0">
      <h1 className="text-2xl md:text-7xl font-bold dark:text-white">
        The Ultimate <br /> development studio
      </h1>
      <p className="max-w-2xl text-base md:text-xl mt-8 dark:text-neutral-200">
        We build beautiful products with the latest technologies and frameworks.
        We are a team of passionate developers and designers that love to build
        amazing products.
      </p>
    </div>
  );
};

export const ProductCard = ({
  product,
  translate,
}: {
  product: {
    title: string;
    description?: string;
    icon?: React.ReactNode;
    link?: string;
    thumbnail?: string;
  };
  translate: MotionValue<number>;
}) => {
  return (
    <motion.div
      style={{
        x: translate,
      }}
      whileHover={{
        y: -20,
      }}
      key={product.title}
      className="group/product relative flex h-[15rem] w-[82vw] max-w-[22rem] shrink-0 cursor-default flex-col items-center justify-center overflow-hidden rounded-3xl border border-slate-800 bg-slate-950/80 p-5 text-center shadow-2xl backdrop-blur-md transition-colors duration-300 hover:border-slate-700 sm:h-80 sm:w-[24rem] sm:p-7 lg:h-96 lg:w-[30rem] lg:p-8"
    >
      {/* Background ambient glow effect */}
      <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 via-transparent to-purple-500/5 opacity-0 group-hover/product:opacity-100 transition-opacity duration-500 pointer-events-none"></div>
      
      {/* Radial highlighting on hover */}
      <div className="absolute pointer-events-none inset-0 flex items-center justify-center bg-black/20 group-hover/product:bg-black/0 transition-colors duration-500 [mask-image:radial-gradient(ellipse_at_center,black,transparent_75%)]"></div>

      <div className="relative z-10 mb-6 opacity-80 transition-all duration-500 ease-out group-hover/product:-translate-y-2 group-hover/product:scale-110 group-hover/product:opacity-100 sm:mb-8">
        {product.icon}
      </div>

      <h2 className="relative z-10 mb-3 text-xl font-bold tracking-tight text-slate-100 transition-colors duration-300 group-hover/product:text-white sm:mb-4 sm:text-2xl">
        {product.title}
      </h2>

      <p className="relative z-10 mx-auto max-w-[220px] text-xs leading-relaxed text-slate-400 transition-colors duration-300 group-hover/product:text-slate-300 sm:max-w-[240px] sm:text-sm md:text-base">
        {product.description}
      </p>

    </motion.div>
  );
};
