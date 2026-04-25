import { useCallback, useEffect, useRef, useState } from 'react';
import {
  motion,
  useMotionTemplate,
  useMotionValue,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
} from 'framer-motion';
import { Link } from 'react-router-dom';
import Canvas3D from '../components/Canvas3D';
import { EncryptedText } from '../components/ui/encrypted-text';
import { HeroParallax } from '../components/ui/hero-parallax';
import { products as parallaxProducts } from '../components/hero-parallax-demo';
import {
  ArrowRight,
  Bot,
  Radar,
  ShieldAlert,
  FileText,
  Sparkles,
  Globe2,
  DatabaseZap,
  Link2,
  Binary,
  ShieldCheck,
  Cpu,
  TimerReset,
  BadgeCheck,
} from 'lucide-react';
import './Home.css';

const sectionReveal = {
  features: {
    initial: { opacity: 0, y: 42, scale: 0.98, filter: 'blur(8px)' },
    whileInView: { opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' },
    transition: { type: 'spring', stiffness: 120, damping: 18, mass: 0.75 },
  },
  signal: {
    initial: { opacity: 0, scaleX: 0.92, y: 20, filter: 'blur(5px)' },
    whileInView: { opacity: 1, scaleX: 1, y: 0, filter: 'blur(0px)' },
    transition: { duration: 0.66, ease: [0.16, 1, 0.3, 1] },
  },
  bentoHead: {
    initial: { opacity: 0, y: 26, rotateX: -8, filter: 'blur(6px)' },
    whileInView: { opacity: 1, y: 0, rotateX: 0, filter: 'blur(0px)' },
    transition: { duration: 0.62, ease: [0.22, 1, 0.36, 1] },
  },
  workflow: {
    initial: { opacity: 0, y: 24, scale: 0.985 },
    whileInView: { opacity: 1, y: 0, scale: 1 },
    transition: { duration: 0.58, ease: [0.22, 1, 0.36, 1] },
  },
  useCasesHead: {
    initial: { opacity: 0, x: -36, y: 10, filter: 'blur(6px)' },
    whileInView: { opacity: 1, x: 0, y: 0, filter: 'blur(0px)' },
    transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] },
  },
  resultsHead: {
    initial: { opacity: 0, x: 36, y: 10, filter: 'blur(6px)' },
    whileInView: { opacity: 1, x: 0, y: 0, filter: 'blur(0px)' },
    transition: { duration: 0.62, ease: [0.16, 1, 0.3, 1] },
  },
  faqHead: {
    initial: { opacity: 0, y: 20, letterSpacing: '0.08em' },
    whileInView: { opacity: 1, y: 0, letterSpacing: '0em' },
    transition: { duration: 0.56, ease: [0.2, 0.9, 0.2, 1] },
  },
  cta: {
    initial: { opacity: 0, y: 30, scale: 0.96, filter: 'blur(8px)' },
    whileInView: { opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' },
    transition: { duration: 0.68, ease: [0.16, 1, 0.3, 1] },
  },
};

const featureCards = [
  {
    icon: Bot,
    title: 'Autonomous Security Agents',
    description:
      'Crew-based AI agents continuously map attack surfaces, trigger scans, and adapt strategy to your infrastructure changes.',
  },
  {
    icon: Radar,
    title: 'Continuous Multi-Tool Scanning',
    description:
      'SentinelAI orchestrates scanner pipelines for web, network, and API layers so visibility stays fresh, not stale.',
  },
  {
    icon: ShieldAlert,
    title: 'Risk-First Vulnerability Triage',
    description:
      'Findings are prioritized by exploitability and business impact so teams fix what matters first.',
  },
  {
    icon: FileText,
    title: 'Client Portal And Reporting',
    description:
      'Give stakeholders clean dashboards, status tracking, and exportable reports without exposing internal complexity.',
  },
];

const workflow = [
  {
    step: '01',
    title: 'Discover',
    text: 'AI agents inventory domains, hosts, endpoints, and shadow assets.',
  },
  {
    step: '02',
    title: 'Assess',
    text: 'Automated scan chains run with context-aware templates and timing.',
  },
  {
    step: '03',
    title: 'Correlate',
    text: 'Raw scanner outputs are normalized and deduplicated into clear risks.',
  },
  {
    step: '04',
    title: 'Act',
    text: 'Teams track remediation in one place with audit-ready evidence.',
  },
];

const signalStrip = [
  'External Surface Intelligence',
  'Agentic Recon Loops',
  'API Exposure Mapping',
  'Exploitability Scoring',
  'Proof-Ready Reporting',
  'Continuous Validation',
  'Noise-Free Deduplication',
];

const bentoCapabilities = [
  {
    icon: Globe2,
    title: 'Global Asset Graph',
    description:
      'Domain, subdomain, and endpoint relationships are mapped into one living topology to expose hidden attack paths.',
    size: 'wide',
  },
  {
    icon: DatabaseZap,
    title: 'Telemetry Fusion',
    description: 'Scanner outputs, HTTP fingerprints, DNS traces, and contextual metadata are stitched into one signal stream.',
    size: 'normal',
  },
  {
    icon: Link2,
    title: 'Attack Chain Links',
    description: 'Cross-finding correlation highlights escalation routes rather than isolated low-context findings.',
    size: 'normal',
  },
  {
    icon: Binary,
    title: 'Policy As Logic',
    description: 'Define guardrails once and let autonomous agents apply repeatable risk logic across every scan cycle.',
    size: 'normal',
  },
  {
    icon: ShieldCheck,
    title: 'Assurance Ledger',
    description: 'Every action, severity change, and remediation state is tracked with timestamped audit evidence.',
    size: 'wide',
  },
];

const useCases = [
  {
    icon: Cpu,
    title: 'Red Team Enablement',
    text: 'Feed teams with constantly refreshed weak points before formal engagements begin.',
  },
  {
    icon: TimerReset,
    title: 'Fast Regression Checks',
    text: 'Revalidate repaired vulnerabilities quickly after each deploy to prevent silent re-openings.',
  },
  {
    icon: BadgeCheck,
    title: 'Client-Facing Assurance',
    text: 'Convert technical scan output into client-ready progress narratives with verifiable proof.',
  },
];

const outcomeStats = [
  {
    value: '81%',
    label: 'False-positive reduction after AI correlation',
  },
  {
    value: '3.2x',
    label: 'Faster time-to-priority with risk-first triage',
  },
  {
    value: '94%',
    label: 'Coverage consistency across repeat scan cycles',
  },
  {
    value: '24m',
    label: 'Average initial visibility time for new assets',
  },
];

const faqItems = [
  {
    question: 'Can we keep our current login and project flow?',
    answer:
      'Yes. SentinelAI layers on top of your current dashboard and authentication flow, so teams can adopt it without process disruption.',
  },
  {
    question: 'How does SentinelAI reduce scanner noise?',
    answer:
      'It correlates repeated findings across tools, de-duplicates evidence, and ranks issues by exploitability and business context.',
  },
  {
    question: 'Is this only for large enterprise environments?',
    answer:
      'No. The workflow scales from smaller web estates to multi-tenant environments through modular scanning strategies.',
  },
  {
    question: 'Can clients see progress without raw technical complexity?',
    answer:
      'Yes. Client portal views summarize status, severity movement, and remediation progress in plain, audit-friendly language.',
  },
];

export default function Home() {
  const rootRef = useRef(null);
  const reducedMotion = useReducedMotion();
  const [isCompactViewport, setIsCompactViewport] = useState(() =>
    typeof window === 'undefined' ? false : window.innerWidth < 900,
  );

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const onResize = () => setIsCompactViewport(window.innerWidth < 900);
    onResize();
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const pointerX = useMotionValue(0);
  const pointerY = useMotionValue(0);
  const smoothPointerX = useSpring(pointerX, { stiffness: 85, damping: 22, mass: 0.35 });
  const smoothPointerY = useSpring(pointerY, { stiffness: 85, damping: 22, mass: 0.35 });

  const { scrollYProgress } = useScroll({
    target: rootRef,
    offset: ['start start', 'end end'],
  });

  const spotlightX = useTransform(smoothPointerX, [-1, 1], ['38%', '62%']);
  const spotlightY = useTransform(smoothPointerY, [-1, 1], ['30%', '70%']);
  const spotlightBackground = useMotionTemplate`radial-gradient(circle at ${spotlightX} ${spotlightY}, rgba(138, 230, 255, 0.22), rgba(138, 230, 255, 0.06) 30%, transparent 64%)`;

  const heroY = useTransform(scrollYProgress, [0, 0.34], [0, -72]);
  const heroOpacity = useTransform(scrollYProgress, [0, 0.4], [1, 0.55]);
  const featuresY = useTransform(scrollYProgress, [0.14, 0.48], [44, 0]);
  const featuresOpacity = useTransform(scrollYProgress, [0.14, 0.45], [0.45, 1]);

  const handlePointerMove = useCallback(
    (event) => {
      if (reducedMotion || isCompactViewport) return;

      const bounds = event.currentTarget.getBoundingClientRect();
      const x = (event.clientX - bounds.left) / bounds.width;
      const y = (event.clientY - bounds.top) / bounds.height;

      pointerX.set((x - 0.5) * 2);
      pointerY.set((y - 0.5) * 2);
    },
    [pointerX, pointerY, reducedMotion, isCompactViewport],
  );

  const handlePointerLeave = useCallback(() => {
    if (isCompactViewport) return;
    pointerX.set(0);
    pointerY.set(0);
  }, [pointerX, pointerY, isCompactViewport]);

  return (
    <motion.div
      ref={rootRef}
      className="at-home"
      onMouseMove={isCompactViewport ? undefined : handlePointerMove}
      onMouseLeave={isCompactViewport ? undefined : handlePointerLeave}
    >
      <motion.div
        className="at-home__scroll-bar"
        style={reducedMotion ? undefined : { scaleX: scrollYProgress }}
      />
      <div className="at-home__grid" />
      <div className="at-home__noise" />
      <motion.div
        className="at-home__spotlight"
        style={reducedMotion || isCompactViewport ? undefined : { backgroundImage: spotlightBackground }}
      />
      <div className="at-home__blob at-home__blob--a" />
      <div className="at-home__blob at-home__blob--b" />
      <div className="at-home__blob at-home__blob--c" />

      {/* Ambient WebGL background */}
      <Canvas3D className="at-home__ambient-canvas" variant="ambient" />

      <header className="at-home__header">
        <Link to="/" className="at-home__brand" aria-label="SentinelAI home">
          <img src="/resources/logo.svg" alt="SentinelAI" />
          <span>SentinelAI</span>
        </Link>

        <div className="at-home__header-actions">
          <Link to="/login" className="at-home__btn at-home__btn--ghost">
            Login
          </Link>
          <Link to="/subscription" className="at-home__btn at-home__btn--solid">
            Services
            <ArrowRight size={16} />
          </Link>
        </div>
      </header>

      <HeroParallax products={parallaxProducts}>
        <motion.section
          className="at-home__hero w-full mx-auto flex flex-col items-center justify-center pt-0 pb-10 sm:pb-14 md:pb-20 px-4 sm:px-6"
          style={reducedMotion ? undefined : { y: heroY, opacity: heroOpacity }}
        >
          <motion.p
            className="at-home__eyebrow mb-4 sm:mb-6 text-[11px] sm:text-xs"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <Sparkles size={14} />
            AI-Native Offensive Security Platform
          </motion.p>

          <div className="relative z-10 mb-6 sm:mb-8 md:mt-4 flex flex-col items-center justify-center">
            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1, duration: 0.8, ease: 'easeInOut' }}
              className="bg-transparent bg-clip-text text-center text-4xl sm:text-5xl font-bold tracking-tight leading-[1.1] text-white md:text-7xl"
            >
              <EncryptedText
                text="Detect Real Risk"
                encryptedClassName="text-slate-600"
                revealedClassName="text-white"
                revealDelayMs={60}
              />
              <br />
              <EncryptedText
                text="Before Attackers Do"
                encryptedClassName="text-slate-600"
                revealedClassName="text-white"
                revealDelayMs={60}
              />
            </motion.h1>
          </div>

          <motion.p
            className="at-home__subtitle text-center mx-auto mb-8 sm:mb-10 text-base sm:text-lg md:text-xl text-slate-300 px-1"
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.18 }}
          >
            SentinelAI unifies autonomous discovery, intelligent scanning, and vulnerability triage into one high-speed workflow for modern teams.
          </motion.p>

          <motion.div
            className="at-home__hero-actions relative z-20 mb-10 flex w-full max-w-xl flex-col items-stretch justify-center gap-3 sm:mb-14 sm:w-auto sm:max-w-none sm:flex-row sm:items-center"
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.28 }}
          >
            <Link to="/subscription" className="at-home__btn at-home__btn--solid at-home__btn--hero pointer-events-auto w-full sm:w-auto">
              Launch Service Console
              <ArrowRight size={16} />
            </Link>
            <Link to="/login" className="at-home__btn at-home__btn--ghost at-home__btn--hero pointer-events-auto w-full sm:w-auto">
              Go To Login
            </Link>
          </motion.div>

        </motion.section>
      </HeroParallax>

      <main className="at-home__content">




        <motion.section
          className="at-home__features"
          style={reducedMotion ? undefined : { y: featuresY, opacity: featuresOpacity }}
          initial={reducedMotion ? undefined : sectionReveal.features.initial}
          whileInView={reducedMotion ? undefined : sectionReveal.features.whileInView}
          viewport={{ once: true, amount: 0.2 }}
          transition={reducedMotion ? undefined : sectionReveal.features.transition}
        >
          {featureCards.map((feature, idx) => {
            const Icon = feature.icon;
            return (
              <motion.article
                key={feature.title}
                className="at-home__feature-card"
                initial={
                  reducedMotion
                    ? undefined
                    : {
                        opacity: 0,
                        y: idx % 2 === 0 ? 30 : -30,
                        x: idx % 2 === 0 ? -16 : 16,
                        rotate: idx % 2 === 0 ? -1.2 : 1.2,
                      }
                }
                whileInView={reducedMotion ? undefined : { opacity: 1, y: 0, x: 0, rotate: 0 }}
                viewport={{ once: true, amount: 0.35 }}
                transition={
                  reducedMotion
                    ? undefined
                    : {
                        type: 'spring',
                        stiffness: 150,
                        damping: 16,
                        delay: idx * 0.09,
                      }
                }
              >
                <div className="at-home__feature-icon">
                  <Icon size={20} />
                </div>
                <h3>{feature.title}</h3>
                <p>{feature.description}</p>
              </motion.article>
            );
          })}
        </motion.section>

        <motion.section
          className="at-home__signal-strip"
          aria-label="platform signals"
          initial={reducedMotion ? undefined : sectionReveal.signal.initial}
          whileInView={reducedMotion ? undefined : sectionReveal.signal.whileInView}
          viewport={{ once: true, amount: 0.5 }}
          transition={reducedMotion ? undefined : sectionReveal.signal.transition}
        >
          <div className="at-home__signal-track">
            {[...signalStrip, ...signalStrip].map((signal, idx) => (
              <span key={`${signal}-${idx}`}>{signal}</span>
            ))}
          </div>
        </motion.section>

        <section className="at-home__bento">
          <motion.div
            className="at-home__section-head"
            initial={reducedMotion ? undefined : sectionReveal.bentoHead.initial}
            whileInView={reducedMotion ? undefined : sectionReveal.bentoHead.whileInView}
            viewport={{ once: true, amount: 0.35 }}
            transition={reducedMotion ? undefined : sectionReveal.bentoHead.transition}
          >
            <p>Platform Design Language</p>
            <h2>Purpose-Built For Modern Offensive Security Teams</h2>
          </motion.div>

          <div className="at-home__bento-grid">
            {bentoCapabilities.map((item, idx) => {
              const Icon = item.icon;
              return (
                <motion.article
                  key={item.title}
                  className="at-home__bento-card"
                  data-size={item.size}
                  initial={
                    reducedMotion
                      ? undefined
                      : {
                          opacity: 0,
                          y: 18,
                          x: idx % 2 === 0 ? -14 : 14,
                          scale: 0.96,
                          rotateZ: idx % 2 === 0 ? -0.9 : 0.9,
                        }
                  }
                  whileInView={
                    reducedMotion ? undefined : { opacity: 1, y: 0, x: 0, scale: 1, rotateZ: 0 }
                  }
                  viewport={{ once: true, amount: 0.25 }}
                  transition={
                    reducedMotion
                      ? undefined
                      : {
                          duration: 0.48,
                          ease: idx % 2 === 0 ? [0.22, 1, 0.36, 1] : [0.34, 1.56, 0.64, 1],
                          delay: idx * 0.07,
                        }
                  }
                >
                  <div className="at-home__bento-icon">
                    <Icon size={18} />
                  </div>
                  <h3>{item.title}</h3>
                  <p>{item.description}</p>
                </motion.article>
              );
            })}
          </div>
        </section>

        <motion.section
          className="at-home__workflow"
          initial={reducedMotion ? undefined : sectionReveal.workflow.initial}
          whileInView={reducedMotion ? undefined : sectionReveal.workflow.whileInView}
          viewport={{ once: true, amount: 0.24 }}
          transition={reducedMotion ? undefined : sectionReveal.workflow.transition}
        >
          <motion.h2
            initial={reducedMotion ? undefined : { opacity: 0, y: 14, scale: 0.99 }}
            whileInView={reducedMotion ? undefined : { opacity: 1, y: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.65 }}
            transition={reducedMotion ? undefined : { duration: 0.5, ease: [0.2, 0.9, 0.2, 1] }}
          >
            How SentinelAI Runs Your Security Cycle
          </motion.h2>
          <div className="at-home__workflow-grid">
            {workflow.map((item, idx) => (
              <motion.article
                key={item.step}
                initial={
                  reducedMotion
                    ? undefined
                    : {
                        opacity: 0,
                        y: idx % 2 === 0 ? 24 : -24,
                        x: idx % 2 === 0 ? -10 : 10,
                        rotate: idx % 2 === 0 ? -1 : 1,
                      }
                }
                whileInView={reducedMotion ? undefined : { opacity: 1, y: 0, x: 0, rotate: 0 }}
                viewport={{ once: true, amount: 0.35 }}
                transition={
                  reducedMotion
                    ? undefined
                    : {
                        type: 'spring',
                        stiffness: 165,
                        damping: 17,
                        delay: idx * 0.09,
                      }
                }
              >
                <span>{item.step}</span>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
              </motion.article>
            ))}
          </div>
        </motion.section>

        <section className="at-home__use-cases">
          <motion.div
            className="at-home__section-head"
            initial={reducedMotion ? undefined : sectionReveal.useCasesHead.initial}
            whileInView={reducedMotion ? undefined : sectionReveal.useCasesHead.whileInView}
            viewport={{ once: true, amount: 0.35 }}
            transition={reducedMotion ? undefined : sectionReveal.useCasesHead.transition}
          >
            <p>Operational Use Cases</p>
            <h2>From Continuous Recon To Client Assurance</h2>
          </motion.div>

          <div className="at-home__use-case-grid">
            {useCases.map((item, idx) => {
              const Icon = item.icon;
              return (
                <motion.article
                  key={item.title}
                  className="at-home__use-case-card"
                  initial={
                    reducedMotion
                      ? undefined
                      : {
                          opacity: 0,
                          y: 14,
                          rotateY: idx % 2 === 0 ? -22 : 22,
                          transformPerspective: 900,
                        }
                  }
                  whileInView={
                    reducedMotion ? undefined : { opacity: 1, y: 0, rotateY: 0, transformPerspective: 900 }
                  }
                  viewport={{ once: true, amount: 0.3 }}
                  transition={
                    reducedMotion
                      ? undefined
                      : {
                          duration: 0.58,
                          ease: [0.16, 1, 0.3, 1],
                          delay: idx * 0.11,
                        }
                  }
                >
                  <div className="at-home__use-case-icon">
                    <Icon size={20} />
                  </div>
                  <h3>{item.title}</h3>
                  <p>{item.text}</p>
                </motion.article>
              );
            })}
          </div>
        </section>

        <section className="at-home__results">
          <motion.div
            className="at-home__section-head"
            initial={reducedMotion ? undefined : sectionReveal.resultsHead.initial}
            whileInView={reducedMotion ? undefined : sectionReveal.resultsHead.whileInView}
            viewport={{ once: true, amount: 0.35 }}
            transition={reducedMotion ? undefined : sectionReveal.resultsHead.transition}
          >
            <p>Measured Outcomes</p>
            <h2>Security Programs Move Faster With Clearer Priority</h2>
          </motion.div>

          <div className="at-home__results-grid">
            {outcomeStats.map((item, idx) => (
              <motion.article
                key={item.label}
                className="at-home__result-card"
                initial={
                  reducedMotion
                    ? undefined
                    : {
                        opacity: 0,
                        y: 26,
                        scale: 0.88,
                        filter: 'blur(8px)',
                      }
                }
                whileInView={
                  reducedMotion ? undefined : { opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' }
                }
                viewport={{ once: true, amount: 0.3 }}
                transition={
                  reducedMotion
                    ? undefined
                    : {
                        type: 'spring',
                        stiffness: 180,
                        damping: 16,
                        delay: idx * 0.08,
                      }
                }
              >
                <h3>{item.value}</h3>
                <p>{item.label}</p>
              </motion.article>
            ))}
          </div>
        </section>

        <section className="at-home__faq">
          <motion.div
            className="at-home__section-head"
            initial={reducedMotion ? undefined : sectionReveal.faqHead.initial}
            whileInView={reducedMotion ? undefined : sectionReveal.faqHead.whileInView}
            viewport={{ once: true, amount: 0.35 }}
            transition={reducedMotion ? undefined : sectionReveal.faqHead.transition}
          >
            <p>Questions</p>
            <h2>Everything Teams Ask Before Rollout</h2>
          </motion.div>

          <div className="at-home__faq-list">
            {faqItems.map((item, idx) => (
              <motion.details
                key={item.question}
                className="at-home__faq-item"
                initial={
                  reducedMotion
                    ? undefined
                    : {
                        opacity: 0,
                        x: idx % 2 === 0 ? -14 : 14,
                        y: 12,
                        clipPath: 'inset(0 100% 0 0 round 14px)',
                      }
                }
                whileInView={
                  reducedMotion
                    ? undefined
                    : {
                        opacity: 1,
                        x: 0,
                        y: 0,
                        clipPath: 'inset(0 0% 0 0 round 14px)',
                      }
                }
                viewport={{ once: true, amount: 0.35 }}
                transition={
                  reducedMotion
                    ? undefined
                    : {
                        duration: 0.54,
                        ease: [0.2, 0.9, 0.2, 1],
                        delay: idx * 0.06,
                      }
                }
              >
                <summary>{item.question}</summary>
                <p>{item.answer}</p>
              </motion.details>
            ))}
          </div>
        </section>

        <motion.section
          className="at-home__cta"
          initial={reducedMotion ? undefined : sectionReveal.cta.initial}
          whileInView={reducedMotion ? undefined : sectionReveal.cta.whileInView}
          viewport={{ once: true, amount: 0.4 }}
          transition={reducedMotion ? undefined : sectionReveal.cta.transition}
        >
          <motion.h2
            initial={reducedMotion ? undefined : { opacity: 0, y: 12 }}
            whileInView={reducedMotion ? undefined : { opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.8 }}
            transition={reducedMotion ? undefined : { duration: 0.44, delay: 0.06 }}
          >
            Ready To Run SentinelAI On Your Targets?
          </motion.h2>
          <motion.p
            initial={reducedMotion ? undefined : { opacity: 0, y: 14 }}
            whileInView={reducedMotion ? undefined : { opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.8 }}
            transition={reducedMotion ? undefined : { duration: 0.46, delay: 0.12 }}
          >
            Keep your current login and dashboard flow, now with a high-impact homepage experience in front.
          </motion.p>
          <motion.div
            className="at-home__cta-actions"
            initial={reducedMotion ? undefined : { opacity: 0, y: 12, scale: 0.98 }}
            whileInView={reducedMotion ? undefined : { opacity: 1, y: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.8 }}
            transition={reducedMotion ? undefined : { duration: 0.5, delay: 0.18 }}
          >
            <motion.div whileHover={reducedMotion ? undefined : { y: -3, scale: 1.02 }} whileTap={{ scale: 0.98 }}>
              <Link to="/subscription" className="at-home__btn at-home__btn--solid at-home__btn--hero">
                Open Services
                <ArrowRight size={16} />
              </Link>
            </motion.div>
            <motion.div
              whileHover={reducedMotion ? undefined : { y: -3, scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              transition={{ delay: 0.04 }}
            >
              <Link to="/login" className="at-home__btn at-home__btn--ghost at-home__btn--hero">
                Open Login
              </Link>
            </motion.div>
          </motion.div>
        </motion.section>
      </main>
    </motion.div>
  );
}
